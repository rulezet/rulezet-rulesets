rule sig_03e342ac636ce2978e8a4e795c483ff6918f0ef90a663316df124524a6b1 {
  meta:
    description = "datamaliciousorder - file 03e342ac636ce2978e8a4e795c483ff6918f0ef90a663316df124524a6b162d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03e342ac636ce2978e8a4e795c483ff6918f0ef90a663316df124524a6b162d2"

  strings:
    $s1 = "        shell.Run(nnNote, 0, false);" fullword ascii
    $s2 = "if (shell) {" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}