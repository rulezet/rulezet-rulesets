rule sig_20160525_2271b0d7a3fd286f29c9dc2ddbbaecee {
  meta:
    description = "datamaliciousorder - file 20160525_2271b0d7a3fd286f29c9dc2ddbbaecee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1189c2a821eff2bd5d5f117e55af52f816674e632f69672459b650339c4abe29"

  strings:
    $s1  = "th.round((Math.pow(Math.sin(895), 2) + Math.pow(Math.cos(895), 2) - 1))-603)) FmJtkoWPdKhSwA += DP(RIxFnMKGY);else if (JUBDihzmu" ascii
    $s2  = "function DHspaoFaWUd(elkmWjeOeMrpT) {var mVWnOOxiegIadZimdnijFerk = RpQAmElGekVnz.join(UYGVcyEkjdIrOzUZc[0]);var RIxFnMKGY, wJge" ascii
    $s3  = "th.cos(808), 2) - 1))-326) & 0xff;wJgelBNkgemAntqBAjaST = UNKMLtVGercgCWC>> (122 + Math.round((Math.pow(Math.sin(871), 2) + Math" ascii
    $s4  = "function TitRzviPjakUDrPmBN(WoMGiSkgzQndQtphPRN,aNWAisDhTzf){return WoMGiSkgzQndQtphPRN.charAt(aNWAisDhTzf);}" fullword ascii
    $s5  = "RIxFnMKGY, wJgelBNkgemAntqBAjaST);else FmJtkoWPdKhSwA += EsuJTQAaJZG(RIxFnMKGY, wJgelBNkgemAntqBAjaST, uzgJPmidGWXMUWDUXqjaz);} " ascii
    $s6  = "while (QtMoBBxUHboAoskVGOv < elkmWjeOeMrpT.length);return FmJtkoWPdKhSwA;}" fullword ascii
    $s7  = "function DP(oNUIosjLgmVSTlPzNrIMnJ){return String.fromCharCode(oNUIosjLgmVSTlPzNrIMnJ);}" fullword ascii
    $s8  = "function EsuJTQAaJZG(AoCnIAymlSQoGXzBTiY,xLWQQXDETkFgDJlcN,qtBeM){return String.fromCharCode(AoCnIAymlSQoGXzBTiY,xLWQQXDETkFgDJl" ascii
    $s9  = "function EsuJTQAaJZG(AoCnIAymlSQoGXzBTiY,xLWQQXDETkFgDJlcN,qtBeM){return String.fromCharCode(AoCnIAymlSQoGXzBTiY,xLWQQXDETkFgDJl" ascii
    $s10 = "function DHspaoFaWUd(elkmWjeOeMrpT) {var mVWnOOxiegIadZimdnijFerk = RpQAmElGekVnz.join(UYGVcyEkjdIrOzUZc[0]);var RIxFnMKGY, wJge" ascii
    $s11 = "function SjfOIawjwEONeVFjOBTqt(WuyALnWlmRJBCGxONHmi,hCThTTscPgRBEjXFGbUFpbvJ){return WuyALnWlmRJBCGxONHmi.indexOf(hCThTTscPgRBEj" ascii
    $s12 = "function SjfOIawjwEONeVFjOBTqt(WuyALnWlmRJBCGxONHmi,hCThTTscPgRBEjXFGbUFpbvJ){return WuyALnWlmRJBCGxONHmi.indexOf(hCThTTscPgRBEj" ascii
    $s13 = "function zRlZzoOrL(kvaRRpFemwEMNQZpdk,aAppMZt){return String.fromCharCode(kvaRRpFemwEMNQZpdk,aAppMZt);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}