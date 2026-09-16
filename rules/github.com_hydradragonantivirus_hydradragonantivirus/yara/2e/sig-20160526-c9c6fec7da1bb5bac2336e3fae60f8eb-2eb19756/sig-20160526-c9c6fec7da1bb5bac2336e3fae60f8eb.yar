rule sig_20160526_c9c6fec7da1bb5bac2336e3fae60f8eb {
  meta:
    description = "datamaliciousorder - file 20160526_c9c6fec7da1bb5bac2336e3fae60f8eb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7068212c6928e0e66474e6278a82f24b4caaecfee43a63097af891fb7880dc5d"

  strings:
    $s1  = "), 2) - 1))-59)) DJjFspZb += rv(fAfEoVcRpiAZqGvyewMMVmuF);else if (UMBCxCSkNCI == (570 + Math.round((Math.pow(Math.sin(763), 2) " ascii
    $s2  = "LnQDiPYCZZxo(EihxwliCjbpcv,kvpODmJoxtM++));SNQTBBjEYl = tVvpzkX<< (777 + Math.round((Math.pow(Math.sin(555), 2) + Math.pow(Math." ascii
    $s3  = "+ Math.pow(Math.cos(763), 2) - 1))-506)) DJjFspZb += nKcArqPNjOXyUTY(fAfEoVcRpiAZqGvyewMMVmuF, aFOGDFQnMMldUKyzZ);else DJjFspZb " ascii
    $s4  = "function VZsNw(EihxwliCjbpcv) {var saGpbeZuQCaVvCxTNPk = LbmsVgD.join(stGkDmxPHbhWaMmWuSb[0]);var fAfEoVcRpiAZqGvyewMMVmuF, aFOG" ascii
    $s5  = "function UdqwdjfeILnQDiPYCZZxo(BuPBkWOCfSQzqBXOpgJQMN,LGjJUFUngtIfuNr){return BuPBkWOCfSQzqBXOpgJQMN.charAt(LGjJUFUngtIfuNr);}" fullword ascii
    $s6  = "+= SbNTKYchxjh(fAfEoVcRpiAZqGvyewMMVmuF, aFOGDFQnMMldUKyzZ, iTyyLIhUz);} while (kvpODmJoxtM < EihxwliCjbpcv.length);return DJjFs" ascii
    $s7  = "function SbNTKYchxjh(mXWSLMco,IklWIxSICJMMaIxDI,WyVxXjkTCIKVU){return String.fromCharCode(mXWSLMco,IklWIxSICJMMaIxDI,WyVxXjkTCIK" ascii
    $s8  = "function OLtlZEBvjlojXVy(nYDYDTpBfDLHexUGap,CdoMwEaBqbL){return nYDYDTpBfDLHexUGap.indexOf(CdoMwEaBqbL);}" fullword ascii
    $s9  = "function SbNTKYchxjh(mXWSLMco,IklWIxSICJMMaIxDI,WyVxXjkTCIKVU){return String.fromCharCode(mXWSLMco,IklWIxSICJMMaIxDI,WyVxXjkTCIK" ascii
    $s10 = "function rv(jslJFgopqcGujQichUwQOb){return String.fromCharCode(jslJFgopqcGujQichUwQOb);}" fullword ascii
    $s11 = "function nKcArqPNjOXyUTY(DMbFydBWmxUEzztxCI,cVwpwONqmWRdawPuzvKf){return String.fromCharCode(DMbFydBWmxUEzztxCI,cVwpwONqmWRdawPu" ascii
    $s12 = "function nKcArqPNjOXyUTY(DMbFydBWmxUEzztxCI,cVwpwONqmWRdawPuzvKf){return String.fromCharCode(DMbFydBWmxUEzztxCI,cVwpwONqmWRdawPu" ascii
    $s13 = "function VZsNw(EihxwliCjbpcv) {var saGpbeZuQCaVvCxTNPk = LbmsVgD.join(stGkDmxPHbhWaMmWuSb[0]);var fAfEoVcRpiAZqGvyewMMVmuF, aFOG" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}