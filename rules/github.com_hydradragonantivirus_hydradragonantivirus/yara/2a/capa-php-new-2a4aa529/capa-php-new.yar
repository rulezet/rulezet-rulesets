rule capa_php_new: WEBSHELL PROD {
  meta:
    description = "PHP tags, only <?= and <?php. Use only if needed to reduce false positives because it won't find includer shells anymore. (e.g. <? include 'webshell.txt'?> and the payload in webshell.txt without <? )"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/14"

  strings:
    $new_php1  = /<\?=[\w\s@$]/ wide ascii
    $new_php2  = "<?php" nocase wide ascii
    $new_php3  = "<script language=\"php" nocase wide ascii
    $php_short = "<?"

  condition:
    any of ($new_php*) or
    $php_short at 0
}