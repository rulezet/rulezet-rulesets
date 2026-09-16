rule sig_20170417_7353fdbf8df5fe2a35327c281d8aa117 {
  meta:
    description = "datamaliciousorder - file 20170417_7353fdbf8df5fe2a35327c281d8aa117.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f0fee417942e4daf98409880d97bbcce825dc957f7b708a67e200260b3fe5eb"

  strings:
    $s1 = "if (DEzkvfiLCJQrltaGxTp.FolderExists(\"c:\\\\windOwS\") == true) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}