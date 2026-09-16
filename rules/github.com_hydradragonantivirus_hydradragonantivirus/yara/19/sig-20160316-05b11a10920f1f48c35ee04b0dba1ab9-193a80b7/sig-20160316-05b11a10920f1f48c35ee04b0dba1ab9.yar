rule sig_20160316_05b11a10920f1f48c35ee04b0dba1ab9 {
  meta:
    description = "datamaliciousorder - file 20160316_05b11a10920f1f48c35ee04b0dba1ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14314accb21c2ea94378e985b35450e522c46f51b644b8d4f76d55c7192d974c"

  strings:
    $s1 = "while (ZpkMdwgCDobrChc[pCrPhXSZPcj + YkNADO + XDJLAXbsnp + YBTEy + nUMoskEz] < 4 ) {WScript[QLXPgdMETP + OvNWHhJh + EZOjEZV](100" ascii
    $s2 = "while (ZpkMdwgCDobrChc[pCrPhXSZPcj + YkNADO + XDJLAXbsnp + YBTEy + nUMoskEz] < 4 ) {WScript[QLXPgdMETP + OvNWHhJh + EZOjEZV](100" ascii
    $s3 = "ZpkMdwgCDobrChc[upB + CIVovsOooo + gkreBDFRsVSpXn](hEsAITP, egtPg + LtJktpUWAcE + bwZWRi + uWutGHM + OTvzCT + hxJkaJDQ + thY + m" ascii
    $s4 = "function GBKrbpGIa(n){return JkMRYBhF + AGZxpSRlciJFal + iFtaBaMJglTf + ghHltB + XnTIqXPdhhnP + UqMeVDvXCg + mWEm;}" fullword ascii
    $s5 = "QZMCrOTtiNuO + vRTRl + ClHD + DNXfTZYSOvWX + fqbDOToY + PuIncztXAiUH + DQWBUWQDbaMzqDa + bavUsnjuz + tDjwtwJhu, false);" fullword ascii
    $s6 = "function RlXVErIJyxq(rGWNwWEZ){SWcRfc[IhbBbuUoAa](rGWNwWEZ, 0, 0);}" fullword ascii
    $s7 = "var kHRWRPwocUd = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}