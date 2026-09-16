rule sig_20151217_a3a8c46fa920d92773f00351deb25fc3 {
  meta:
    description = "datamaliciousorder - file 20151217_a3a8c46fa920d92773f00351deb25fc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9a7980a3e0f4d5ce9da49311756331116db2a2a34edbcec61d135397ad8fca2"

  strings:
    $s1  = "ath.cos(74), 2) - 1)));} vCyjXpCNK[bNsFcfKeMVR]++;}bNsFcfKeMVR++;} return BgBnaPaqpfC}" fullword ascii
    $s2  = "h.pow(Math.cos(89), 2) - 1)); while(true) { if(vCyjXpCNK[bNsFcfKeMVR] > kfVkt[bNsFcfKeMVR].length-(-67+908)/841) { break; } if (" ascii
    $s3  = "function AFespZyPZvAKeGFfg(kfVkt){BgBnaPaqpfC= '';bNsFcfKeMVR=Math.round((Math.pow(Math.sin(458), 2) + Math.pow(Math.cos(458), 2" ascii
    $s4  = ") - 1));while(true){if (bNsFcfKeMVR >= (5089+905)/999){break;}vCyjXpCNK[bNsFcfKeMVR]=Math.round((Math.pow(Math.sin(89), 2) + Mat" ascii
    $s5  = "function AFespZyPZvAKeGFfg(kfVkt){BgBnaPaqpfC= '';bNsFcfKeMVR=Math.round((Math.pow(Math.sin(458), 2) + Math.pow(Math.cos(458), 2" ascii
    $s6  = "function YaVcxkC(YKBUdYNXBtzpPCPrFaHCpkgxJPjATdeDJoSm) {return !IpmQWFvUWLN(PUONIHpDmfWovvR(YKBUdYNXBtzpPCPrFaHCpkgxJPjATdeDJoSm" ascii
    $s7  = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s8  = "function NsQedNsnviyjCCPIl(sRaSartFXw,dIudYHLgRE) {return parseInt(sRaSartFXw,dIudYHLgRE);}" fullword ascii
    $s9  = "function CPsEXfWWYRrenfpDTgHiJakXnjOAGqNASDmAXSffqUusGdjSUvOgmI(aTUodTUqnBryp,vGeABZYDbCNNVv){ return MPodVae[UJLblXfb[GkUQR(aTU" ascii
    $s10 = "function iDosDzvcBFzb(yYJObImwKpKdG) {return isFinite(yYJObImwKpKdG);}" fullword ascii
    $s11 = "function P(HLguEGNVdEfIUC,vfKuCTCHkOMYd,ajJCbIhoZmE) {HLguEGNVdEfIUC[vfKuCTCHkOMYd]=ajJCbIhoZmE;}" fullword ascii
    $s12 = "function GkUQR(fNerKcgTnNz,aveRlYkimzQbx,dvRXaHFX){nlKx=NsQedNsnviyjCCPIl(fNerKcgTnNz,aveRlYkimzQbx);uyTek=nlKx.toString(dvRXaHF" ascii
    $s13 = "function IpmQWFvUWLN(yaXDWFHhsnDXbZ) {return isNaN(yaXDWFHhsnDXbZ);}" fullword ascii
    $s14 = "function wlHWuKpjSbrcScq(rJhTjPtYqWKlpsaEs,GNaCfHadsbeeBxBforyVNCiLMZQgwRufYa,uXGLubHiquQSbWHPHIAxdNrZPVApOPdpJtw){eval(rJhTjPtY" ascii
    $s15 = "function PUONIHpDmfWovvR(qQObyPtbdLKVYGeIgbx) {return parseFloat(qQObyPtbdLKVYGeIgbx);}" fullword ascii
    $s16 = "function GkUQR(fNerKcgTnNz,aveRlYkimzQbx,dvRXaHFX){nlKx=NsQedNsnviyjCCPIl(fNerKcgTnNz,aveRlYkimzQbx);uyTek=nlKx.toString(dvRXaHF" ascii
    $s17 = "var p = new Array();p[0]=[];p[0][0]='d';p[0][1]='a';p[0][2]='d';p[0][3]='a';p[0][4]='46';p[0][5]='3d';p[0][6]='42';p[0][7]='14';" ascii
    $s18 = "function YaVcxkC(YKBUdYNXBtzpPCPrFaHCpkgxJPjATdeDJoSm) {return !IpmQWFvUWLN(PUONIHpDmfWovvR(YKBUdYNXBtzpPCPrFaHCpkgxJPjATdeDJoSm" ascii
    $s19 = "X);return uyTek;}" fullword ascii
    $s20 = "function wlHWuKpjSbrcScq(rJhTjPtYqWKlpsaEs,GNaCfHadsbeeBxBforyVNCiLMZQgwRufYa,uXGLubHiquQSbWHPHIAxdNrZPVApOPdpJtw){eval(rJhTjPtY" ascii

  condition:
    uint16(0) == 0x4a55 and
    8 of them
}