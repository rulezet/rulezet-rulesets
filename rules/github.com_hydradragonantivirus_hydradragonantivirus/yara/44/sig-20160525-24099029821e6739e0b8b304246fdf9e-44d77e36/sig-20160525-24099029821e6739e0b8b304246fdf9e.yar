rule sig_20160525_24099029821e6739e0b8b304246fdf9e {
  meta:
    description = "datamaliciousorder - file 20160525_24099029821e6739e0b8b304246fdf9e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8431d53124ebb6dd21fef36317b59c009fe0d05f72227a67cd3116b81059135c"

  strings:
    $s1  = "(913), 2) - 1))-932) & 0xff;bcRxXEnwjYXBzurtZAUcHM = AXyiVgJYXXdOItcjbR & 0xff;if (PXthbQnS == (926 + Math.round((Math.pow(Math." ascii
    $s2  = "function DpCRSMNZ(BSjRatCZgiFVm) {var RGUfdnOsrsLDXKvj = SqxJfUjLuHQwCJbY.join(KYYHhMSfcxpePd[0]);var lnlaMxMEZBAq, hjMtSswkOHVp" ascii
    $s3  = "sin(291), 2) + Math.pow(Math.cos(291), 2) - 1))-862)) sPikyRtpbn += IB(lnlaMxMEZBAq);else if (SFfoBKSYA == (172 + Math.round((Ma" ascii
    $s4  = "function mVjdR(EHBXOg,krlRaVauIBIzXPGeQnjQMj){return EHBXOg.charAt(krlRaVauIBIzXPGeQnjQMj);}" fullword ascii
    $s5  = "function IB(YVtgnbhKcBapla){return String.fromCharCode(YVtgnbhKcBapla);}" fullword ascii
    $s6  = "function DpCRSMNZ(BSjRatCZgiFVm) {var RGUfdnOsrsLDXKvj = SqxJfUjLuHQwCJbY.join(KYYHhMSfcxpePd[0]);var lnlaMxMEZBAq, hjMtSswkOHVp" ascii
    $s7  = "function fnEDlmTGTLoBMJlvkgcv(dOdNPYSwzG,lvDuNQFY){return String.fromCharCode(dOdNPYSwzG,lvDuNQFY);}" fullword ascii
    $s8  = "ength);return sPikyRtpbn;}" fullword ascii
    $s9  = "function TUmVDkGuCNEKpz(sdmaY,CEQBWAVaHQbGAxHcCII){return sdmaY.indexOf(CEQBWAVaHQbGAxHcCII);}" fullword ascii
    $s10 = "Gs);else sPikyRtpbn += TnnLEXlPXggQUDWa(lnlaMxMEZBAq, hjMtSswkOHVpyGs, bcRxXEnwjYXBzurtZAUcHM);} while (fTiDfm < BSjRatCZgiFVm.l" ascii
    $s11 = "function TnnLEXlPXggQUDWa(fWAoiSJfuXQcADPN,TiuqhlCSsGKB,nizJiHcKxqygzMooyeTvz){return String.fromCharCode(fWAoiSJfuXQcADPN,Tiuqh" ascii
    $s12 = "function TnnLEXlPXggQUDWa(fWAoiSJfuXQcADPN,TiuqhlCSsGKB,nizJiHcKxqygzMooyeTvz){return String.fromCharCode(fWAoiSJfuXQcADPN,Tiuqh" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}