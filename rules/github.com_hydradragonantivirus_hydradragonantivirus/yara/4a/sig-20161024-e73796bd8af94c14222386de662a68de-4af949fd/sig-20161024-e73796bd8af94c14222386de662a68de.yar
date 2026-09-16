rule sig_20161024_e73796bd8af94c14222386de662a68de {
  meta:
    description = "datamaliciousorder - file 20161024_e73796bd8af94c14222386de662a68de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "be587232ebf38ef3210432ceb53f398229b17215cc630b8264e8ce9d7bbd8cc9"

  strings:
    $s1 = "} while (yh++ < kp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}