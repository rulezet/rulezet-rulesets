rule sig_20170416_68b9d93cf2e09972f4a97556d730e2f2 {
  meta:
    description = "datamaliciousorder - file 20170416_68b9d93cf2e09972f4a97556d730e2f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4903c81bbc12050439f0e44cf46015afef78fb79fb152c6a6b39305e00e71155"

  strings:
    $s1 = "if (qcRXLeVhaQKgfxysvu.FolderExists(\"c:\\\\windows\") == true) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}