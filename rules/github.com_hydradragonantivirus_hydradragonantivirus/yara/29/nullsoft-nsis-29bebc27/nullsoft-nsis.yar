rule Nullsoft_NSIS: NullSoft {
  meta:
    author      = "_pusher_"
    description = "Nullsoft Installer"
    date        = "2016-01"
    version     = "0.2"

  strings:
    $c0 = { EF BE AD DE 4E 75 6C 6C 73 6F 66 74 49 6E 73 74 }
        $c1 = { 5C 54 65 6D 70 00 00 00 4E 53 49 53 20 45 72 72 6F 72 00 00 FF FF FF FF }

  condition:
    $c0 or $c1
}