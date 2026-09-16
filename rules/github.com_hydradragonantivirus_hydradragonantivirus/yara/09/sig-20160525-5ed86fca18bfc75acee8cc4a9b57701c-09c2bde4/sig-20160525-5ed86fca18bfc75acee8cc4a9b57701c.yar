rule sig_20160525_5ed86fca18bfc75acee8cc4a9b57701c {
  meta:
    description = "datamaliciousorder - file 20160525_5ed86fca18bfc75acee8cc4a9b57701c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19d4848728627cd54728cdc8ddcc53c12a252e9148e8ce43acfa4fa7da633422"

  strings:
    $s1 = "e rav\\n;\"ak96x\\\\\" = rerednere rav\\n;\".d6x\\\\66x\\\\\" = eixodf rav\\n;\"e2x\\\\zw\" = gsmf rav;};dnenoisillocf nruter{)d" ascii

  condition:
    uint16(0) == 0x200a and
    all of them
}