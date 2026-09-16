rule sig_20160315_02968ec005e544cf8ad1e4e845ad6693 {
  meta:
    description = "datamaliciousorder - file 20160315_02968ec005e544cf8ad1e4e845ad6693.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "36e952b3df9b27ebd28aed6561023aed4c67c39066750715dc2fcfcd49cb66d5"

  strings:
    $s1 = "while (qfLBjfGyNMaaedu.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s2 = "function DSBNinOwbq(TOCeIDlT){WshShell[iRLH](TOCeIDlT, 0, 0);}" fullword ascii
    $s3 = "function ywO(n){return Lvlkaeu + TbvRHCXVSNSroc + ppKvaxYupq + JDPXCkmnJElxvc + lxbPXOccqid + JMcvr + lKFYUxUgP + WqnNZ + RhwUYX" ascii
    $s4 = "Wn + GBQrFUZw + IBojD + UWghpVUAn + vPMfulBVyfQz, false);" fullword ascii
    $s5 = "function ywO(n){return Lvlkaeu + TbvRHCXVSNSroc + ppKvaxYupq + JDPXCkmnJElxvc + lxbPXOccqid + JMcvr + lKFYUxUgP + WqnNZ + RhwUYX" ascii
    $s6 = "var gfXidPsctMLw = new Date();" fullword ascii
    $s7 = "qfLBjfGyNMaaedu[VFfiofCDbdtS + XRYIA + ijQxv](NzeHNFC, QxnqhMVndsyQLpx + ADFJHS + UjTjnnGuHscA + xEXcLoitGMspbzJ + EncBWBts + lP" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}