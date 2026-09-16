rule sig_20151209_c0c2d254a2a6c965f2366f70feb645de {
  meta:
    description = "datamaliciousorder - file 20151209_c0c2d254a2a6c965f2366f70feb645de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b52a86dfd07cf201ae834459af9fc52fd16273b71e940cf72df64d0a09ff7f79"

  strings:
    $s1  = "var jzRNjSrxpSDTk=[];for(SKcOmLq=(-979+979)/780;SKcOmLq<(62438+282)/490;SKcOmLq++){jzRNjSrxpSDTk[SKcOmLq]=String.fromCharCode(SK" ascii
    $s2  = "cOmLq)}function MrQiI(cmiArCESRbE,PwJQucWYyvCgT,lqGbhEkl){XERK=parseInt(cmiArCESRbE,PwJQucWYyvCgT);WkiED=XERK.toString(lqGbhEkl)" ascii
    $s3  = "function ATJoMWi(VfQoJXDyRmUaJEAFrtPGjkPdZsqEmHUqrWrY) {return !isNaN(parseFloat(VfQoJXDyRmUaJEAFrtPGjkPdZsqEmHUqrWrY)) && isFin" ascii
    $s4  = "function ATJoMWi(VfQoJXDyRmUaJEAFrtPGjkPdZsqEmHUqrWrY) {return !isNaN(parseFloat(VfQoJXDyRmUaJEAFrtPGjkPdZsqEmHUqrWrY)) && isFin" ascii
    $s5  = "push(\"83\");b.push(\"99\");b.push(\"114\");b.push(\"105\");b.push(\"34\");b.push(\"58\");b.push(\"34\");b.push(\"34\");b.push(" ascii
    $s6  = "function oVHYHerWrrqtEExZXUpMZRsczvNFJUxfNjzwNmgIvCeGTfqLDIacEr(yMeTcuNtOJsXR,JpvMTCUPKdZREw){ return jzRNjSrxpSDTk[MrQiI(yMeTcu" ascii
    $s7  = "function dqxsdvYtTkonHrmvm(GIYOc){ubuKlFlnpFp= '';for(ydkBkVSTcbz=(-91+91)/484; ydkBkVSTcbz < (1563+177)/870; ydkBkVSTcbz++) {OM" ascii
    $s8  = "push(\"61\");g.push(\"32\");g.push(\"48\");g.push(\"59\");g.push(\"13\");g.push(\"10\");g.push(\"32\");g.push(\"32\");g.push(\"1" ascii
    $s9  = "push(\"47\");b.push(\"42\");b.push(\"79\");b.push(\"53\");b.push(\"115\");b.push(\"78\");b.push(\"49\");b.push(\"55\");b.push(\"" ascii
    $s10 = ";return WkiED;}function CktLPEsiYGbBmTo(ZnVzFOxGmItgGnevj){eval(ZnVzFOxGmItgGnevj)}" fullword ascii
    $s11 = "push(\"10\");g.push(\"9\");g.push(\"105\");g.push(\"102\");g.push(\"32\");g.push(\"40\");g.push(\"86\");g.push(\"84\");g.push(\"" ascii
    $s12 = "push(\"32\");b.push(\"48\");b.push(\"59\");b.push(\"13\");b.push(\"10\");b.push(\"118\");b.push(\"97\");b.push(\"114\");b.push(" ascii
    $s13 = ";}} return ubuKlFlnpFp}" fullword ascii
    $s14 = "function crnuzbbrOkE(OrHCYfIZ,NUBmfP){return OrHCYfIZ.split(NUBmfP)}" fullword ascii
    $s15 = "function dqxsdvYtTkonHrmvm(GIYOc){ubuKlFlnpFp= '';for(ydkBkVSTcbz=(-91+91)/484; ydkBkVSTcbz < (1563+177)/870; ydkBkVSTcbz++) {OM" ascii
    $s16 = "function oVHYHerWrrqtEExZXUpMZRsczvNFJUxfNjzwNmgIvCeGTfqLDIacEr(yMeTcuNtOJsXR,JpvMTCUPKdZREw){ return jzRNjSrxpSDTk[MrQiI(yMeTcu" ascii
    $s17 = "PebuBBE[ydkBkVSTcbz]=(-362+362)/554; while(true) { if(OMPebuBBE[ydkBkVSTcbz] > GIYOc[ydkBkVSTcbz].length-(259+376)/635) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}