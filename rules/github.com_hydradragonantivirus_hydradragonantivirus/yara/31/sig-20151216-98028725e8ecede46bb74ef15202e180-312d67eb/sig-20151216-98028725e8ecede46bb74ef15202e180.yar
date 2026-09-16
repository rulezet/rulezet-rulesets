rule sig_20151216_98028725e8ecede46bb74ef15202e180 {
  meta:
    description = "datamaliciousorder - file 20151216_98028725e8ecede46bb74ef15202e180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77405e6bf54e340fd44d1b9caf1e1bebeb5b3f2ab92c0aa10600a133f68a6926"

  strings:
    $s1  = ".cos(135), 2) - 1)));} vCxAvSWGk[jsjAqXTcqYg]++;}jsjAqXTcqYg++;} return JnlsFgEHJnn}" fullword ascii
    $s2  = "ow(Math.cos(38), 2) - 1)); while(true) { if(vCxAvSWGk[jsjAqXTcqYg] > iSBBh[jsjAqXTcqYg].length-(634+92)/726) { break; } if (iWxI" ascii
    $s3  = "function XZGqaOmUdgLUKreiL(iSBBh){JnlsFgEHJnn= '';jsjAqXTcqYg=Math.round((Math.pow(Math.sin(87), 2) + Math.pow(Math.cos(87), 2) " ascii
    $s4  = "function XZGqaOmUdgLUKreiL(iSBBh){JnlsFgEHJnn= '';jsjAqXTcqYg=Math.round((Math.pow(Math.sin(87), 2) + Math.pow(Math.cos(87), 2) " ascii
    $s5  = "- 1));while(true){if (jsjAqXTcqYg >= (3702+42)/624){break;}vCxAvSWGk[jsjAqXTcqYg]=Math.round((Math.pow(Math.sin(38), 2) + Math.p" ascii
    $s6  = "xfefwarsEPqtlAXFmFigUoWVfKc([iSBBh[jsjAqXTcqYg][vCxAvSWGk[jsjAqXTcqYg]]], Math.round((Math.pow(Math.sin(135), 2) + Math.pow(Math" ascii
    $s7  = "function aVSqg(hFAULRfCSku,cCcpWFNDPNrhA,KEnvNzHw){BVbk=qaRZjCypDlHCOmzky(hFAULRfCSku,cCcpWFNDPNrhA);EeeKs=BVbk.toString(KEnvNzH" ascii
    $s8  = "function qaRZjCypDlHCOmzky(FpZGOvXKVW,ANRYoGqpeD) {return parseInt(FpZGOvXKVW,ANRYoGqpeD);}" fullword ascii
    $s9  = "function iWxIbQp(gCTayelrgXphQXgqZOhZzlbGCZOcsLXzkDdY) {return !XWTrrpmjIck(QFaAVestsLCCoNC(gCTayelrgXphQXgqZOhZzlbGCZOcsLXzkDdY" ascii
    $s10 = "function aVSqg(hFAULRfCSku,cCcpWFNDPNrhA,KEnvNzHw){BVbk=qaRZjCypDlHCOmzky(hFAULRfCSku,cCcpWFNDPNrhA);EeeKs=BVbk.toString(KEnvNzH" ascii
    $s11 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s12 = "function wSVCXoywOnAZ(mMUrqCTPFszcS) {return isFinite(mMUrqCTPFszcS);}" fullword ascii
    $s13 = "w);return EeeKs;}" fullword ascii
    $s14 = "function XWTrrpmjIck(ojKDtPHwUVwguG) {return isNaN(ojKDtPHwUVwguG);}" fullword ascii
    $s15 = "function QFaAVestsLCCoNC(CDbBpolaPAZyRFDDyCp) {return parseFloat(CDbBpolaPAZyRFDDyCp);}" fullword ascii
    $s16 = "var s = new Array();s[0]=[];s[0][0]='d';s[0][1]='a';s[0][2]='d';s[0][3]='a';s[0][4]='46';s[0][5]='3d';s[0][6]='42';s[0][7]='14';" ascii
    $s17 = ",'V','Z','p','@','0','`','W','#','f','9','5','X','>','G','K','w','[','Y','z','o',';','_','Z',':','6','t','t','&','[','U',String." ascii
    $s18 = "function iWxIbQp(gCTayelrgXphQXgqZOhZzlbGCZOcsLXzkDdY) {return !XWTrrpmjIck(QFaAVestsLCCoNC(gCTayelrgXphQXgqZOhZzlbGCZOcsLXzkDdY" ascii
    $s19 = "function v(NpEqAAMfKcbfyr,PQqGFvjQYcHsn,BtoEXgfnmEj) {NpEqAAMfKcbfyr[PQqGFvjQYcHsn]=BtoEXgfnmEj;}" fullword ascii
    $s20 = "function ZrsFcDomGJqEwjHhYKplkboMZYAxfefwarsEPqtlAXFmFigUoWVfKc(hPLSalTIYUhWP,TFCTHxUKzcySCe){ return aMzRIij[TdKvBWlv[aVSqg(hPL" ascii

  condition:
    uint16(0) == 0x6454 and
    8 of them
}