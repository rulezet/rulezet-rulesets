rule sig_20160316_f3d63a5869a421878dbcc059f40a5ddd {
  meta:
    description = "datamaliciousorder - file 20160316_f3d63a5869a421878dbcc059f40a5ddd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc44421dcf0bc2f2dc1f23183d35e0e1e3b64ad918d4fd541c7d3a7b501f8249"

  strings:
    $s1 = "while (dEpNrSiNWTLMNMP[WzTlJfsrveGOil + kaOhooevktlDXzi + HdqrwJQJngby + EuI] < 4 ) {WScript[iUAOvGdWR + wPmz + ANgCAgQMEdSi + E" ascii
    $s2 = "while (dEpNrSiNWTLMNMP[WzTlJfsrveGOil + kaOhooevktlDXzi + HdqrwJQJngby + EuI] < 4 ) {WScript[iUAOvGdWR + wPmz + ANgCAgQMEdSi + E" ascii
    $s3 = "dEpNrSiNWTLMNMP[SiwSjdmeDor + jEnqeZyJKsjzX + bfi](tgYTD + Eoz, JKACmWTaMhrYHoj + tmfyrQ + QyjdEZlcGWaiq + yplJ + XEfKasVdURhh +" ascii
    $s4 = "function mOR(ZLejSfG){LnfilInbNmaozIz[qnLOQr + QiOBJ](ZLejSfG, 0, 0);}" fullword ascii
    $s5 = "wd + IWYBi + JwTOmHcjBuTOf + ccnG, false);" fullword ascii
    $s6 = "function VWgSilLaVpksl(n){return uwcRcPWvglpMp + HGfjo + vSMdNwxOyJJz + wBLDUUnlh + sOyRFk + OvjhfxLnDoWTg;}" fullword ascii
    $s7 = "var gQGtAAdXQm = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}