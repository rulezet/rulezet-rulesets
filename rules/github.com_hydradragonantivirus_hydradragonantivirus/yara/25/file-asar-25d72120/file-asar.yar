rule file_asar {
  meta:
    description = "Identify Electron archives bundles (.asar)"
    author      = "@shellcromancer"
    version     = "1.0"
    date        = "2023.02.03"
    reference   = "https://github.com/electron/asar"
    DaysofYARA  = "34/100"

  strings:
    $header = { 04 00 00 00 }
    $key1   = "files"
    $key2   = "integrity"
    $key3   = "offset"

  condition:
    $header at 0 and
    all of them
}