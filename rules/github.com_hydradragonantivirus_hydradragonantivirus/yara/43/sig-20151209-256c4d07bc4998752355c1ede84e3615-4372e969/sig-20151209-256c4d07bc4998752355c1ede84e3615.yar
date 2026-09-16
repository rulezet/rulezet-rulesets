rule sig_20151209_256c4d07bc4998752355c1ede84e3615 {
  meta:
    description = "datamaliciousorder - file 20151209_256c4d07bc4998752355c1ede84e3615.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8ababe2160ef677a796bc4e40034e4c82f268b24c4a4f63d590d88205c37b70"

  strings:
    $s1  = "function dRJDUMJZyhSqGQgUgWFNNGdaZrpcIMhJxAZMWRHGmqXMibSfXIwapC(ZQvDuUIyWsPxr,JnDIEZiMfTmxQG){ return mdpyy[IvrYZ(ZQvDuUIyWsPxr[" ascii
    $s2  = "function dRJDUMJZyhSqGQgUgWFNNGdaZrpcIMhJxAZMWRHGmqXMibSfXIwapC(ZQvDuUIyWsPxr,JnDIEZiMfTmxQG){ return mdpyy[IvrYZ(ZQvDuUIyWsPxr[" ascii
    $s3  = "function eAoejollHuvgtLqAx(EGYYo){rNJLorNEiBU= '';for(NpwINNKxzJX=(-630+630)/838; NpwINNKxzJX < (320+888)/604; NpwINNKxzJX++) {T" ascii
    $s4  = "function IvrYZ(FhYSIPfSxWV,WbrMwbPLCdycU,QXoeFVEw){jwlQ=parseInt(FhYSIPfSxWV,WbrMwbPLCdycU);BbqJn=jwlQ.toString(QXoeFVEw);return" ascii
    $s5  = ";}} return rNJLorNEiBU}" fullword ascii
    $s6  = "function yOmnweWAySb(bTylnYMk,BSEITE){return bTylnYMk.split(BSEITE)}" fullword ascii
    $s7  = "VTiIiVyY[NpwINNKxzJX]=(-764+764)/384; while(true) { if(TVTiIiVyY[NpwINNKxzJX] > EGYYo[NpwINNKxzJX].length-(213+205)/418) { break" ascii
    $s8  = "function IvrYZ(FhYSIPfSxWV,WbrMwbPLCdycU,QXoeFVEw){jwlQ=parseInt(FhYSIPfSxWV,WbrMwbPLCdycU);BbqJn=jwlQ.toString(QXoeFVEw);return" ascii
    $s9  = " BbqJn;}function MYNtnMTXvBDWObj(OpVjdPzlxtYmdijwY){eval(OpVjdPzlxtYmdijwY)}" fullword ascii
    $s10 = "function ZCANMFp(tYyrQxrNlHNsKiPmnhCnmiMYLGjWfeJsMOsX) {return !isNaN(parseFloat(tYyrQxrNlHNsKiPmnhCnmiMYLGjWfeJsMOsX)) && isFin" ascii
    $s11 = "function ZCANMFp(tYyrQxrNlHNsKiPmnhCnmiMYLGjWfeJsMOsX) {return !isNaN(parseFloat(tYyrQxrNlHNsKiPmnhCnmiMYLGjWfeJsMOsX)) && isFin" ascii
    $s12 = "function eAoejollHuvgtLqAx(EGYYo){rNJLorNEiBU= '';for(NpwINNKxzJX=(-630+630)/838; NpwINNKxzJX < (320+888)/604; NpwINNKxzJX++) {T" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}