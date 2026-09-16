rule sig_20160526_50164f27ff08776121f008bc0c4dedfb {
  meta:
    description = "datamaliciousorder - file 20160526_50164f27ff08776121f008bc0c4dedfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4159ceec4b89ff52b985c34aecc3d0c5a106537aefbfe9a63daf748d24fd303c"

  strings:
    $s1  = "w(Math.cos(389), 2) - 1))-934)) vkCuKLGQIWaspSfuONQ += wuaxHgxHWzupYRjWfVdrn(jtPnWWJV, OtyffaTPiaiW);else vkCuKLGQIWaspSfuONQ +=" ascii
    $s2  = "function GCEiv(kxNexXBACNxeT) {var OyvxsddXHVWwOXYRyUHMSVH = dwDKnNdXsQsrVUq.join(SiAiQvak[0]);var jtPnWWJV, OtyffaTPiaiW, azjVW" ascii
    $s3  = "function PkJEthgmoZOtnNeykwAeo(pUBPmMPxTUcBugUHOWNpvn,tRSqNZemyMpLYAsPqUmJkJC){return pUBPmMPxTUcBugUHOWNpvn.charAt(tRSqNZemyMpL" ascii
    $s4  = "function PkJEthgmoZOtnNeykwAeo(pUBPmMPxTUcBugUHOWNpvn,tRSqNZemyMpLYAsPqUmJkJC){return pUBPmMPxTUcBugUHOWNpvn.charAt(tRSqNZemyMpL" ascii
    $s5  = "1))-756)) vkCuKLGQIWaspSfuONQ += bEX(jtPnWWJV);else if (IaqOWKuBcABsy == (998 + Math.round((Math.pow(Math.sin(389), 2) + Math.po" ascii
    $s6  = "function wuaxHgxHWzupYRjWfVdrn(QsBwRgHpfuKEpPjREXhuwpq,QapaNbUBScjNDbiPPrV){return String.fromCharCode(QsBwRgHpfuKEpPjREXhuwpq,Q" ascii
    $s7  = "function ibRShLMTen(xsPjFvOpfPDpEc,AjOIoy,WsHPXUjRSCqVmutLWaAFhee){return String.fromCharCode(xsPjFvOpfPDpEc,AjOIoy,WsHPXUjRSCqV" ascii
    $s8  = "function wuaxHgxHWzupYRjWfVdrn(QsBwRgHpfuKEpPjREXhuwpq,QapaNbUBScjNDbiPPrV){return String.fromCharCode(QsBwRgHpfuKEpPjREXhuwpq,Q" ascii
    $s9  = "function ibRShLMTen(xsPjFvOpfPDpEc,AjOIoy,WsHPXUjRSCqVmutLWaAFhee){return String.fromCharCode(xsPjFvOpfPDpEc,AjOIoy,WsHPXUjRSCqV" ascii
    $s10 = "function LRuixylqulAfzHcrzLuV(LnkbhTKMXZMKMYegkKoZuhGr,teHZlyTfRUA){return LnkbhTKMXZMKMYegkKoZuhGr.indexOf(teHZlyTfRUA);}" fullword ascii
    $s11 = " ibRShLMTen(jtPnWWJV, OtyffaTPiaiW, azjVWGJuH);} while (JHXiKbzAIqGXD < kxNexXBACNxeT.length);return vkCuKLGQIWaspSfuONQ;}" fullword ascii
    $s12 = "function bEX(SQVfGQuKQyyx){return String.fromCharCode(SQVfGQuKQyyx);}" fullword ascii
    $s13 = "function GCEiv(kxNexXBACNxeT) {var OyvxsddXHVWwOXYRyUHMSVH = dwDKnNdXsQsrVUq.join(SiAiQvak[0]);var jtPnWWJV, OtyffaTPiaiW, azjVW" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}