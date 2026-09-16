rule sig_20151215_2e29450137f16c5bf0b3cc980cd7367b {
  meta:
    description = "datamaliciousorder - file 20151215_2e29450137f16c5bf0b3cc980cd7367b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c331edf0aebdf14692ee1257ea1c25c4b8cc92377dec0da2c82fece9df15beb"

  strings:
    $s1  = "ath.pow(Math.cos(825), 2) - 1)); while(true) { if(KLFjrAOtq[eAItZPXeNHu] > PNyAA[eAItZPXeNHu].length-(236+370)/606) { break; } i" ascii
    $s2  = "function nKmhVyfAmWHSXPfaj(PNyAA){SJWBxExttoj= S[1773];for(eAItZPXeNHu=Math.round((Math.pow(Math.sin(720), 2) + Math.pow(Math.co" ascii
    $s3  = "pow(Math.cos(483), 2) - 1)));} KLFjrAOtq[eAItZPXeNHu]++;}} return SJWBxExttoj}" fullword ascii
    $s4  = "function nKmhVyfAmWHSXPfaj(PNyAA){SJWBxExttoj= S[1773];for(eAItZPXeNHu=Math.round((Math.pow(Math.sin(720), 2) + Math.pow(Math.co" ascii
    $s5  = "erpxyADHKZqdqtRePiXpciiyuKjKKrYmyji([PNyAA[eAItZPXeNHu][KLFjrAOtq[eAItZPXeNHu]]], Math.round((Math.pow(Math.sin(483), 2) + Math." ascii
    $s6  = "function f(iyYuawrUmPwx,SJwCTJpWhxxygO){iyYuawrUmPwx.push(SJwCTJpWhxxygO);}function x6(EwIezYdLDUHRjueX){if(EJtzavv(EwIezYdLDUHR" ascii
    $s7  = "jueX)) {return (String.fromCharCode(EwIezYdLDUHRjueX) + String.fromCharCode((15509+808)/441));}}" fullword ascii
    $s8  = "function EJtzavv(VygbyFTYiPbeimhXHNlAtQXaaGTxqnlvEyIn) {return !isNaN(parseFloat(VygbyFTYiPbeimhXHNlAtQXaaGTxqnlvEyIn)) && isFin" ascii
    $s9  = "function EJtzavv(VygbyFTYiPbeimhXHNlAtQXaaGTxqnlvEyIn) {return !isNaN(parseFloat(VygbyFTYiPbeimhXHNlAtQXaaGTxqnlvEyIn)) && isFin" ascii
    $s10 = "function sQmnp(QYmAzyvuLTE,CITPoGqcrXiPB,DoqIidGk){RaUr=parseInt(QYmAzyvuLTE,CITPoGqcrXiPB);pWEgF=RaUr.toString(DoqIidGk);return" ascii
    $s11 = " pWEgF;}function cytuWTqVMDmXvvE(erfULzdmxChBIvoWy,etpsHjlAdJvGzHNLyZuYyuOjsZfnDdGOSV,jRhsgTXfvlZRCKsTcYvbqaUcnzQEmRyqMgl){eval(" ascii
    $s12 = "function f(iyYuawrUmPwx,SJwCTJpWhxxygO){iyYuawrUmPwx.push(SJwCTJpWhxxygO);}function x6(EwIezYdLDUHRjueX){if(EJtzavv(EwIezYdLDUHR" ascii
    $s13 = "function esJjqGWrwPmophwpaPwerpxyADHKZqdqtRePiXpciiyuKjKKrYmyji(ISnEYIIDPXTzn,jNbeKlLQrBAHqF){ return YaypMYb[HsXUJrgs[sQmnp(ISn" ascii
    $s14 = "function sQmnp(QYmAzyvuLTE,CITPoGqcrXiPB,DoqIidGk){RaUr=parseInt(QYmAzyvuLTE,CITPoGqcrXiPB);pWEgF=RaUr.toString(DoqIidGk);return" ascii
    $s15 = "function rRVjFcnpYQH(ueWQetrY,ICcTLV){return ueWQetrY.split(ICcTLV)}" fullword ascii
    $s16 = "function esJjqGWrwPmophwpaPwerpxyADHKZqdqtRePiXpciiyuKjKKrYmyji(ISnEYIIDPXTzn,jNbeKlLQrBAHqF){ return YaypMYb[HsXUJrgs[sQmnp(ISn" ascii
    $s17 = "function cytuWTqVMDmXvvE(erfULzdmxChBIvoWy){eval(erfULzdmxChBIvoWy)}" fullword ascii
    $s18 = "var S=new Array();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}