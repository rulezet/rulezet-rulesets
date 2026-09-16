rule sig_20151215_7604bfd3331ea2064710afbd1a60ece0 {
  meta:
    description = "datamaliciousorder - file 20151215_7604bfd3331ea2064710afbd1a60ece0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8fb66029fc7137b2db66970d6c13773c10a9f71870db6867d5be3c41772e388"

  strings:
    $s1  = "function RiekGhlzCfsKJuFfv(GCRYG){ZHdazpEKzdj= V[1754];for(lKWLAHtULLk=Math.round((Math.pow(Math.sin(496), 2) + Math.pow(Math.co" ascii
    $s2  = "(Math.cos(707), 2) - 1)));} zQTBKTydh[lKWLAHtULLk]++;}} return ZHdazpEKzdj}" fullword ascii
    $s3  = ".pow(Math.cos(934), 2) - 1)); while(true) { if(zQTBKTydh[lKWLAHtULLk] > GCRYG[lKWLAHtULLk].length-(182+817)/999) { break; } if (" ascii
    $s4  = "s(496), 2) - 1)); lKWLAHtULLk < (27+95)/61; lKWLAHtULLk++) {zQTBKTydh[lKWLAHtULLk]=Math.round((Math.pow(Math.sin(934), 2) + Math" ascii
    $s5  = "function RiekGhlzCfsKJuFfv(GCRYG){ZHdazpEKzdj= V[1754];for(lKWLAHtULLk=Math.round((Math.pow(Math.sin(496), 2) + Math.pow(Math.co" ascii
    $s6  = "function z(dBlGnzcbKwBM,zEPZRFIcLMODaO){dBlGnzcbKwBM.push(zEPZRFIcLMODaO);}function G9(FxJvcwIsgaJvTAbY){if(fPlcopR(FxJvcwIsgaJv" ascii
    $s7  = "TAbY)) {return (String.fromCharCode(FxJvcwIsgaJvTAbY) + String.fromCharCode((44375+247)/603));}}" fullword ascii
    $s8  = "function fPlcopR(GEHCbVlhxYUgIbYeKxvKmIbUOepLfxINHknT) {return !isNaN(parseFloat(GEHCbVlhxYUgIbYeKxvKmIbUOepLfxINHknT)) && isFin" ascii
    $s9  = "function fPlcopR(GEHCbVlhxYUgIbYeKxvKmIbUOepLfxINHknT) {return !isNaN(parseFloat(GEHCbVlhxYUgIbYeKxvKmIbUOepLfxINHknT)) && isFin" ascii
    $s10 = "var V=new Array();" fullword ascii
    $s11 = " Chkth;}function STZHUecOamutevK(EIFhzvBULNeWeeyZf,hWIbPeyfcvQIGxuEcgAVhMRxxuAyuCNlvx,vgkosrDVNAGuiEdeAAwvvyIIKLfDDFfYaxp){eval(" ascii
    $s12 = "function vsdfV(UqCWOZpxUAr,QjtcHBpsPxddt,pEvgJCjq){JoBC=parseInt(UqCWOZpxUAr,QjtcHBpsPxddt);Chkth=JoBC.toString(pEvgJCjq);return" ascii
    $s13 = "function STZHUecOamutevK(EIFhzvBULNeWeeyZf){eval(EIFhzvBULNeWeeyZf)}" fullword ascii
    $s14 = "function OxEUXAmIheeGiRZasSqBJwEXeNoQniOYYFUAHJYLgBApoBNizsUJIt(VMBReCWHyKcQE,QEBpQUZMUByhIZ){ return XCqurjQ[qQeIqOut[vsdfV(VMB" ascii
    $s15 = "function YjfBJvrUuMk(MNOBXUmL,tcLcyC){return MNOBXUmL.split(tcLcyC)}" fullword ascii
    $s16 = "function z(dBlGnzcbKwBM,zEPZRFIcLMODaO){dBlGnzcbKwBM.push(zEPZRFIcLMODaO);}function G9(FxJvcwIsgaJvTAbY){if(fPlcopR(FxJvcwIsgaJv" ascii
    $s17 = "function vsdfV(UqCWOZpxUAr,QjtcHBpsPxddt,pEvgJCjq){JoBC=parseInt(UqCWOZpxUAr,QjtcHBpsPxddt);Chkth=JoBC.toString(pEvgJCjq);return" ascii
    $s18 = "function OxEUXAmIheeGiRZasSqBJwEXeNoQniOYYFUAHJYLgBApoBNizsUJIt(VMBReCWHyKcQE,QEBpQUZMUByhIZ){ return XCqurjQ[qQeIqOut[vsdfV(VMB" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}