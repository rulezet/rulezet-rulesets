rule sig_20160526_7ffeb3f0d67e46dc7bfc543fcc26c7cc {
  meta:
    description = "datamaliciousorder - file 20160526_7ffeb3f0d67e46dc7bfc543fcc26c7cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "496ff48ea2e8f5f4852e35c225cdcb5649c689d9a7e117fc72e4e086d11769bd"

  strings:
    $s1  = " Math.pow(Math.cos(589), 2) - 1))-382)) UFvUUoFBCpRtiPqQBWfUu += cq(xHqWNlM);else if (frcFKThNvNHAkYk == (311 + Math.round((Math" ascii
    $s2  = "yfeLGKPiF,asbhWrfFGOed(YbjKGDSsOEFCz,kActu++));qhBPuiuRIHgNlWsx = ZHlmRCw<< (671 + Math.round((Math.pow(Math.sin(826), 2) + Math" ascii
    $s3  = "function gstKRSOszjRE(YbjKGDSsOEFCz) {var ECJZZISVarkyfeLGKPiF = tCJtL.join(FUwdbODRMbKoXOqNyWSEYLq[0]);var xHqWNlM, JxzCASYHkUA" ascii
    $s4  = "function asbhWrfFGOed(oyAOODUSHUtU,LwFKajac){return oyAOODUSHUtU.charAt(LwFKajac);}" fullword ascii
    $s5  = "DSsOEFCz.length);return UFvUUoFBCpRtiPqQBWfUu;}" fullword ascii
    $s6  = "function IpPUtRpsWqrMPHMHQvM(owUxdSMkcoDya,LjZspLIFWICBVTEmWTwscRkX){return String.fromCharCode(owUxdSMkcoDya,LjZspLIFWICBVTEmWT" ascii
    $s7  = "function cq(hevrBKpdjPTFkKcxNKiBrfSZ){return String.fromCharCode(hevrBKpdjPTFkKcxNKiBrfSZ);}" fullword ascii
    $s8  = "function IpPUtRpsWqrMPHMHQvM(owUxdSMkcoDya,LjZspLIFWICBVTEmWTwscRkX){return String.fromCharCode(owUxdSMkcoDya,LjZspLIFWICBVTEmWT" ascii
    $s9  = "function YDqINKvQJheDW(NwfvcWpfrJgdnl,ZmEMOQJSZJRwIbPMRJoxG,bMwQVrJUMOKmgtaQ){return String.fromCharCode(NwfvcWpfrJgdnl,ZmEMOQJS" ascii
    $s10 = "function YDqINKvQJheDW(NwfvcWpfrJgdnl,ZmEMOQJSZJRwIbPMRJoxG,bMwQVrJUMOKmgtaQ){return String.fromCharCode(NwfvcWpfrJgdnl,ZmEMOQJS" ascii
    $s11 = "function ATTNEfJudELVCrFveizGoPj(EnkVCwWuoHtJXsTNzIREa,pPrWAZDFkGubwjjHYvKBi){return EnkVCwWuoHtJXsTNzIREa.indexOf(pPrWAZDFkGubw" ascii
    $s12 = "function ATTNEfJudELVCrFveizGoPj(EnkVCwWuoHtJXsTNzIREa,pPrWAZDFkGubwjjHYvKBi){return EnkVCwWuoHtJXsTNzIREa.indexOf(pPrWAZDFkGubw" ascii
    $s13 = "function gstKRSOszjRE(YbjKGDSsOEFCz) {var ECJZZISVarkyfeLGKPiF = tCJtL.join(FUwdbODRMbKoXOqNyWSEYLq[0]);var xHqWNlM, JxzCASYHkUA" ascii
    $s14 = "AOeAIJHeT);else UFvUUoFBCpRtiPqQBWfUu += YDqINKvQJheDW(xHqWNlM, JxzCASYHkUAOeAIJHeT, UotuginemvTpFzePnGE);} while (kActu < YbjKG" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}