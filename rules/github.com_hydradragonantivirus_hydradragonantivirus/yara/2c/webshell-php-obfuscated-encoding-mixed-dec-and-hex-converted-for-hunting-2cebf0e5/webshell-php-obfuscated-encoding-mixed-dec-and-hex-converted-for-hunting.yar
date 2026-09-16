rule webshell_php_obfuscated_encoding_mixed_dec_and_hex__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "PHP webshell obfuscated by encoding of mixed hex and dec"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/04/18"
    score = 40

  strings:
    $mix       = /['"](\w|\\x?[0-9a-f]{2,3})[\\x0-9a-f]{2,20}\\\d{1,3}[\\x0-9a-f]{2,20}\\x[0-9a-f]{2}\\/ wide ascii nocase
    $php_short = "<?" wide ascii
    $no_xml1   = "<?xml version" nocase wide ascii
    $no_xml2   = "<?xml-stylesheet" nocase wide ascii
    $no_asp1   = "<%@LANGUAGE" nocase wide ascii
    $no_asp2   = /<script language="(vb|jscript|c#)/ nocase wide ascii
    $no_pdf    = "<?xpacket"
    $php_new1  = /<\?=[^?]/ wide ascii
    $php_new2  = "<?php" nocase wide ascii
    $php_new3  = "<script language=\"php" nocase wide ascii

  condition:
    (filesize >= 700KB and filesize < 2100KB
    )
    and
    ((($php_short in (0..100) or $php_short in (filesize - 1000..filesize)) and not any of ($no_*)) or any of ($php_new*)) and any of ($mix*)
}