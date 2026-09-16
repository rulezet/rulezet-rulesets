rule webshell_php_in_htaccess__converted_for_hunting: WEBSHELL HUNT_CONVERTED {
  meta:
    key   = "Use Apache .htaccess to execute php code inside .htaccess"
    key   = "https://creativecommons.org/licenses/by-nc/4.0/"
    key   = "Arnim Rupp"
    key   = "2021/01/07"
    score = 40

  strings:
    $hta = "AddType application/x-httpd-php .htaccess" wide ascii

  condition:
    (filesize >= 100KB and filesize < 300KB
    )
    and $hta
}