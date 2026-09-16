rule sig_20151215_6338eebcc5c0edf572fa82b9b63d075c {
  meta:
    description = "datamaliciousorder - file 20151215_6338eebcc5c0edf572fa82b9b63d075c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1380c46e23e207f5901639b6950b82cbe9616fab1246ab228a16e1fafc2100e5"

  strings:
    $s1  = "ath.pow(Math.cos(446), 2) - 1)); while(true) { if(KFiJtPkPc[hzUbhcmdmcc] > YKIQT[hzUbhcmdmcc].length-(-562+933)/371) { break; } " ascii
    $s2  = "function oAyPFhlKRDSRJPPiO(YKIQT){fwOMuhJDKQo= m[1777];for(hzUbhcmdmcc=Math.round((Math.pow(Math.sin(689), 2) + Math.pow(Math.co" ascii
    $s3  = ".pow(Math.cos(403), 2) - 1)));} KFiJtPkPc[hzUbhcmdmcc]++;}} return fwOMuhJDKQo}" fullword ascii
    $s4  = "TBhKpJHmVTePzRQiTKkaENfEETVlDIyzaGqP([YKIQT[hzUbhcmdmcc][KFiJtPkPc[hzUbhcmdmcc]]], Math.round((Math.pow(Math.sin(403), 2) + Math" ascii
    $s5  = "function oAyPFhlKRDSRJPPiO(YKIQT){fwOMuhJDKQo= m[1777];for(hzUbhcmdmcc=Math.round((Math.pow(Math.sin(689), 2) + Math.pow(Math.co" ascii
    $s6  = "function v(zsPUJiZPdaLO,kbsTHDMvVAgZcw){zsPUJiZPdaLO.push(kbsTHDMvVAgZcw);}function g0(tzRmxuCIGXWNrsTi){if(OAqLaVU(tzRmxuCIGXWN" ascii
    $s7  = "rsTi)) {return (String.fromCharCode(tzRmxuCIGXWNrsTi) + String.fromCharCode((13872+996)/354));}}" fullword ascii
    $s8  = "function OAqLaVU(tvpUjWTVDsQCFkSqLsDpjnDavMskpPLxfCcv) {return !isNaN(parseFloat(tvpUjWTVDsQCFkSqLsDpjnDavMskpPLxfCcv)) && isFin" ascii
    $s9  = "function OAqLaVU(tvpUjWTVDsQCFkSqLsDpjnDavMskpPLxfCcv) {return !isNaN(parseFloat(tvpUjWTVDsQCFkSqLsDpjnDavMskpPLxfCcv)) && isFin" ascii
    $s10 = "function cUWaypRkqGEBCUJwSGTBhKpJHmVTePzRQiTKkaENfEETVlDIyzaGqP(HRSwGliWxKTfr,rmrJhWTaCwEufZ){ return hkeVTYq[thTNOsHJ[hdrNM(HRS" ascii
    $s11 = "function hWQXKpolHVl(VYexWKIg,mukvML){return VYexWKIg.split(mukvML)}" fullword ascii
    $s12 = "function hdrNM(XystghcPGAm,hJMYZhTCfhfnq,ObcmZyhS){DOvK=parseInt(XystghcPGAm,hJMYZhTCfhfnq);kcYFQ=DOvK.toString(ObcmZyhS);return" ascii
    $s13 = " kcYFQ;}function zvjJzOtkoYfdrjD(sWyCJWLpLHtokXTeJ,QFJqQyuesaFWyaXMzDQvqJEhWJYBrpEtwr,yTsvPWbDqSDQUsyeSCwvYGStmLFrgtdVcNg){eval(" ascii
    $s14 = "function hdrNM(XystghcPGAm,hJMYZhTCfhfnq,ObcmZyhS){DOvK=parseInt(XystghcPGAm,hJMYZhTCfhfnq);kcYFQ=DOvK.toString(ObcmZyhS);return" ascii
    $s15 = "function zvjJzOtkoYfdrjD(sWyCJWLpLHtokXTeJ){eval(sWyCJWLpLHtokXTeJ)}" fullword ascii
    $s16 = "function v(zsPUJiZPdaLO,kbsTHDMvVAgZcw){zsPUJiZPdaLO.push(kbsTHDMvVAgZcw);}function g0(tzRmxuCIGXWNrsTi){if(OAqLaVU(tzRmxuCIGXWN" ascii
    $s17 = "function cUWaypRkqGEBCUJwSGTBhKpJHmVTePzRQiTKkaENfEETVlDIyzaGqP(HRSwGliWxKTfr,rmrJhWTaCwEufZ){ return hkeVTYq[thTNOsHJ[hdrNM(HRS" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}