rule sig_20160531_ce9dfdda2dbd237998c904af247dc8c6 {
  meta:
    description = "datamaliciousorder - file 20160531_ce9dfdda2dbd237998c904af247dc8c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c8733674ab08cd7dac1f5ec1ff27ab9fdaf3a946ababd4133a88aea309772ca"

  strings:
    $s1  = "var noOPHDNyRAXb=function(){return WScript.CreateObject(hRYkwpiPovTeVuUHxzxPfkj[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function RHljpvWCpDvPUGS(ZptBBgrTEdFuoRpDKDSr,WROEuQfyppgywINAsquNI){return ZptBBgrTEdFuoRpDKDSr.charAt(WROEuQfyppgywINAsquNI);}" ascii
    $s3  = "function rzJbowYkaaHxM(SnOQkXWrURFAQ,dvgDe,uzpuoAfB){QSJOiYAe=SnOQkXWrURFAQ.split(uzpuoAfB);ONJKfaaB = hRYkwpiPovTeVuUHxzxPfkj[0" ascii
    $s4  = "function rL(KcRzUjh){return String.fromCharCode(KcRzUjh);}" fullword ascii
    $s5  = "function PIjYTmygsDpMDP(){return noOPHDNyRAXb.ExpandEnvironmentStrings(krVmpHBNylGheY())}" fullword ascii
    $s6  = "qvEBC += rL(uAeHDohUyU);else if (ZTISCPnQVPopduikwwXHKzCX == 64) EaDBCbEVTNIqvEBC += jygVisd(uAeHDohUyU, PxttPGqlkCcNYL);else Ea" ascii
    $s7  = "function UzAOY(HDmFhMpCWP,TtGKkikPOPIuZ){return HDmFhMpCWP.indexOf(TtGKkikPOPIuZ);}" fullword ascii
    $s8  = "var pHVbROB=function(){return new ActiveXObject(hRYkwpiPovTeVuUHxzxPfkj[1]);}();" fullword ascii
    $s9  = "(CVWowIFdkOL,0x1,0x0)}function hBvOTw(aMVzJTRZqzfB,cnWHfMvHrHDKO,KkefKd){var hsSjkvMqzhWu=aMVzJTRZqzfB.createtextfile(cnWHfMvHrH" ascii
    $s10 = "function pcUFNF(){return rzJbowYkaaHxM(hRYkwpiPovTeVuUHxzxPfkj[11],[2,4,8,10],hRYkwpiPovTeVuUHxzxPfkj[12]);}" fullword ascii
    $s11 = "function nNMNTtTAKdjhD(CFpWOOiqOuhCi) {var qzVXlbzsBopudStyiewqWnNu = xRRSxsinINQBEpMBSXBidprx.join(hRYkwpiPovTeVuUHxzxPfkj[7]);" ascii
    $s12 = "push(\"v\");xRRSxsinINQBEpMBSXBidprx.push(\"w\");xRRSxsinINQBEpMBSXBidprx.push(\"x\");xRRSxsinINQBEpMBSXBidprx.push(\"y\");xRRSx" ascii
    $s13 = "function krVmpHBNylGheY(){return rzJbowYkaaHxM(hRYkwpiPovTeVuUHxzxPfkj[9],[1,5,7],hRYkwpiPovTeVuUHxzxPfkj[10]);}" fullword ascii
    $s14 = "function pluAN(KfDbmLTxSihKnt,CVWowIFdkOL) {var TOwmSlHcYrHCD=[hRYkwpiPovTeVuUHxzxPfkj[15]];KfDbmLTxSihKnt[TOwmSlHcYrHCD[0]]" fullword ascii
    $s15 = "(CVWowIFdkOL,0x1,0x0)}function hBvOTw(aMVzJTRZqzfB,cnWHfMvHrHDKO,KkefKd){var hsSjkvMqzhWu=aMVzJTRZqzfB.createtextfile(cnWHfMvHrH" ascii
    $s16 = "function nNMNTtTAKdjhD(CFpWOOiqOuhCi) {var qzVXlbzsBopudStyiewqWnNu = xRRSxsinINQBEpMBSXBidprx.join(hRYkwpiPovTeVuUHxzxPfkj[7]);" ascii
    $s17 = "function jygVisd(YSFZTTpuQuI,qeDAIUZeWxchZv){return String.fromCharCode(YSFZTTpuQuI,qeDAIUZeWxchZv);}" fullword ascii
    $s18 = "function efACcKH(){return rzJbowYkaaHxM(hRYkwpiPovTeVuUHxzxPfkj[13],[0,3,6],hRYkwpiPovTeVuUHxzxPfkj[14]);}" fullword ascii
    $s19 = "function rzJbowYkaaHxM(SnOQkXWrURFAQ,dvgDe,uzpuoAfB){QSJOiYAe=SnOQkXWrURFAQ.split(uzpuoAfB);ONJKfaaB = hRYkwpiPovTeVuUHxzxPfkj[0" ascii
    $s20 = "DKO,true);hsSjkvMqzhWu.WriteLine(KkefKd);hsSjkvMqzhWu.Close();}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}