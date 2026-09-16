rule sig_20160527_c399352edf860d5b13a5ab92376b483c {
  meta:
    description = "datamaliciousorder - file 20160527_c399352edf860d5b13a5ab92376b483c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f98944d6751d3dda44698227db09cfe6b156c94d642c1964f133e5764be43ef"

  strings:
    $s1  = "function KnIhmzWxXT() {return WScript;}function BtuUIPjKl(){return ltIeyEUDBvWH.ExpandEnvironmentStrings(CHJCBQRZZVqkRS())}" fullword ascii
    $s2  = "function LUneYKncz(qURsNsijRO,aWOrD){return qURsNsijRO.charAt(aWOrD);}" fullword ascii
    $s3  = "var ltIeyEUDBvWH=function(){return KnIhmzWxXT().CreateObject(doAEixOKroNPShHLfLcA[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s4  = "var OymRMfOtyOci = TgXTfuutkVkI.createtextfile(ltIeyEUDBvWH.ExpandEnvironmentStrings(doAEixOKroNPShHLfLcA[2]+doAEixOKroNPShHLfLc" ascii
    $s5  = "GUp += EJAjhugLJtUKGWTyXcB(vlGIMzqFjIScY, IgcjwxC);else UuvaxWGUp += SWUQAVbZqOInLTIYmgnjZv(vlGIMzqFjIScY, IgcjwxC, MrBeqTRaNGiX" ascii
    $s6  = "function SWUQAVbZqOInLTIYmgnjZv(hWuGYNySaNHxLAfao,obnMuaQVedcSgoeXahV,luypF){return String.fromCharCode(hWuGYNySaNHxLAfao,obnMua" ascii
    $s7  = "pAAP);} while (QfnNmGLfWUmoPjPVhCvvk < epIgiWGSJUNyS.length);return UuvaxWGUp;}" fullword ascii
    $s8  = "function SWUQAVbZqOInLTIYmgnjZv(hWuGYNySaNHxLAfao,obnMuaQVedcSgoeXahV,luypF){return String.fromCharCode(hWuGYNySaNHxLAfao,obnMua" ascii
    $s9  = "[14];for(vfPXgQDB=0;vfPXgQDB<OPrHR.length;vfPXgQDB++) {czDvrkwf+=alPQY[OPrHR[vfPXgQDB]];}return czDvrkwf.substring(3,czDvrkwf.le" ascii
    $s10 = "function gEl(BIxxsuyvfQWXYFSuLn){return String.fromCharCode(BIxxsuyvfQWXYFSuLn);}" fullword ascii
    $s11 = "function KsrZqK(TmaqfGaINZSubw,SHvNfB){return TmaqfGaINZSubw.indexOf(SHvNfB);}" fullword ascii
    $s12 = "XpAAP = XsOQInh & 0xff;if (OoHDZpDRAEPPFUoyWyk == 64) UuvaxWGUp += gEl(vlGIMzqFjIScY);else if (EBeaOTTPUimfrxYCKas == 64) UuvaxW" ascii
    $s13 = "function NAPDpIB(epIgiWGSJUNyS) {var fmWYQotN = PCRVClSycaYu.join(doAEixOKroNPShHLfLcA[6]);var vlGIMzqFjIScY, IgcjwxC, MrBeqTRaN" ascii
    $s14 = "function EJAjhugLJtUKGWTyXcB(KhCaIZExYtPtKbNUanmRMT,AGShROisf){return String.fromCharCode(KhCaIZExYtPtKbNUanmRMT,AGShROisf);}" fullword ascii
    $s15 = "var TgXTfuutkVkI=function(){return new ActiveXObject(doAEixOKroNPShHLfLcA[0]);}();" fullword ascii
    $s16 = "function ekFEpylvsUm(){return quRNiUTKA(doAEixOKroNPShHLfLcA[12],[0,3,6],doAEixOKroNPShHLfLcA[13]);}" fullword ascii
    $s17 = "function quRNiUTKA(qieWALWhgpuchq,OPrHR,LmXuSpJRDTLNI){alPQY=qieWALWhgpuchq.split(LmXuSpJRDTLNI);czDvrkwf = doAEixOKroNPShHLfLcA" ascii
    $s18 = "A[3])+String.fromCharCode(92)+doAEixOKroNPShHLfLcA[4],true);" fullword ascii
    $s19 = "function quRNiUTKA(qieWALWhgpuchq,OPrHR,LmXuSpJRDTLNI){alPQY=qieWALWhgpuchq.split(LmXuSpJRDTLNI);czDvrkwf = doAEixOKroNPShHLfLcA" ascii
    $s20 = "push(\"U\");PCRVClSycaYu.push(\"V\");PCRVClSycaYu.push(\"W\");PCRVClSycaYu.push(\"X\");PCRVClSycaYu.push(\"Y\");PCRVClSycaYu.pus" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}