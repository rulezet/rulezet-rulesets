rule capa_bin_files: WEBSHELL PROD {
  meta:
    description = "Detects MZ, dex and zip/jar for exclusion"
    license     = "https://creativecommons.org/licenses/by-nc/4.0/"
    author      = "Arnim Rupp"
    date        = "2021/03/03"

  strings:
    $dex  = { 64 65 (78 | 79) 0a 30 }
    $pack = { 50 41 43 4b 00 00 00 02 00 }
    $rar  = { 52 61 72 21 1A 07 00 }

  condition:
    uint16(0) == 0x5a4d or
        uint16(0) == 0x8b1f or
    $dex at 0 or
    $pack at 0 or
    $rar at 0 or
        uint16(0) == 0x4b50
}