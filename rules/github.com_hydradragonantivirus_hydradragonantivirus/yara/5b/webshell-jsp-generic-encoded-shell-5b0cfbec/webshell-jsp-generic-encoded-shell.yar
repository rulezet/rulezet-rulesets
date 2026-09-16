rule webshell_jsp_generic_encoded_shell: WEBSHELL PROD {
  meta:
    description = "Generic JSP webshell which contains cmd or /bin/bash encoded in ascii ord"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/01/07"
    hash        = "3eecc354390d60878afaa67a20b0802ce5805f3a9bb34e74dd8c363e3ca0ea5c"

  strings:
    $sj0 = /\\\{ ?47, 98, 105, 110, 47, 98, 97, 115, 104/ wide ascii
    $sj1 = /\\\{ ?99, 109, 100\\\}/ wide ascii
    $sj2 = /\\\{ ?99, 109, 100, 46, 101, 120, 101/ wide ascii
    $sj3 = /\\\{ ?47, 98, 105, 110, 47, 98, 97/ wide ascii
    $sj4 = /\\\{ ?106, 97, 118, 97, 46, 108, 97, 110/ wide ascii
    $sj5 = /\\\{ ?101, 120, 101, 99 \\\}/ wide ascii
    $sj6 = /\\\{ ?103, 101, 116, 82, 117, 110/ wide ascii

  condition:
    filesize < 300KB and
    any of ($sj*)
}