rule sig_20161024_780a109b10e6dd164a37078e80549d66 {
  meta:
    description = "datamaliciousorder - file 20161024_780a109b10e6dd164a37078e80549d66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60d65512bae8730778b48b11bc9aa38ca04a37a544167980856786f396f7bf44"

  strings:
    $s1 = "} while (qx++ < hm);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}