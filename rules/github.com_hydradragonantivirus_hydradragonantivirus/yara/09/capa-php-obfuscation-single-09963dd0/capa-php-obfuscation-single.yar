rule capa_php_obfuscation_single: WEBSHELL PROD {
  meta:
    description = "PHP obfuscation functions which can be used on multiple strings"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
    $cobfs1 = "gzinflate" fullword nocase wide ascii
    $cobfs2 = "gzuncompress" fullword nocase wide ascii
    $cobfs3 = "gzdecode" fullword nocase wide ascii
    $cobfs4 = "base64_decode" fullword nocase wide ascii
    $cobfs5 = "pack" fullword nocase wide ascii
    $cobfs6 = "undecode" fullword nocase wide ascii

  condition:
    any of ($cobfs*)
}