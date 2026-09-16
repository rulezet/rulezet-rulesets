rule sig_20151217_ee770643d393bcb8e374d8ccdd65a3d1 {
  meta:
    description = "datamaliciousorder - file 20151217_ee770643d393bcb8e374d8ccdd65a3d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0c407dc55afd3df4e46c486968e0b7482d076d7de52bef3b4f74eed46a58178"

  strings:
    $s1  = "th.pow(Math.cos(115), 2) - 1)); while(true) { if(oZKfrSxsE[QSBPieMjbru] > sJLNh[QSBPieMjbru].length-(-531+987)/456) { break; } i" ascii
    $s2  = ".pow(Math.cos(819), 2) - 1)));} oZKfrSxsE[QSBPieMjbru]++;}QSBPieMjbru++;} return DZVDUsIYNWi}" fullword ascii
    $s3  = "function XoMTvMomiTEwmXtkB(sJLNh){DZVDUsIYNWi= '';QSBPieMjbru=Math.round((Math.pow(Math.sin(652), 2) + Math.pow(Math.cos(652), 2" ascii
    $s4  = ") - 1));while(true){if (QSBPieMjbru >= (3832+824)/776){break;}oZKfrSxsE[QSBPieMjbru]=Math.round((Math.pow(Math.sin(115), 2) + Ma" ascii
    $s5  = "VfpsipLMVKaUkJJqJsqWgEJipPnbYeQOgJJJ([sJLNh[QSBPieMjbru][oZKfrSxsE[QSBPieMjbru]]], Math.round((Math.pow(Math.sin(819), 2) + Math" ascii
    $s6  = "function XoMTvMomiTEwmXtkB(sJLNh){DZVDUsIYNWi= '';QSBPieMjbru=Math.round((Math.pow(Math.sin(652), 2) + Math.pow(Math.cos(652), 2" ascii
    $s7  = "function dnVgZtLZawHfIVu(iprFAAgOJSSuedDMy,DjEhuVhvNLkUnDMxtqsYEFXasTYZicgetI,nJgyKcjklvDwvPEFGiGaTxjzhGXjPZhKnBr){eval(iprFAAgO" ascii
    $s8  = "function dnVgZtLZawHfIVu(iprFAAgOJSSuedDMy,DjEhuVhvNLkUnDMxtqsYEFXasTYZicgetI,nJgyKcjklvDwvPEFGiGaTxjzhGXjPZhKnBr){eval(iprFAAgO" ascii
    $s9  = "function rudVwfL(fcNgCltAqvjfOuJAMVSWkyITffBETmLXzNLu) {return !DADOfDTlYpb(XFvLiQVPnNiCReE(fcNgCltAqvjfOuJAMVSWkyITffBETmLXzNLu" ascii
    $s10 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s11 = "A);return DOMUd;}" fullword ascii
    $s12 = "var c = new Array();c[0]=[];c[0][0]='d';c[0][1]='a';c[0][2]='d';c[0][3]='a';c[0][4]='46';c[0][5]='3d';c[0][6]='42';c[0][7]='14';" ascii
    $s13 = "function DADOfDTlYpb(JKCohptifbehqt) {return isNaN(JKCohptifbehqt);}" fullword ascii
    $s14 = "function fzMAR(aiVsxFsmraK,hfbkdilQaqsXZ,GceyKjDA){UHoA=CZvuajsnghXSfkMEo(aiVsxFsmraK,hfbkdilQaqsXZ);DOMUd=UHoA.toString(GceyKjD" ascii
    $s15 = "function CZvuajsnghXSfkMEo(QDpjZjadQB,EQHiElHqVJ) {return parseInt(QDpjZjadQB,EQHiElHqVJ);}" fullword ascii
    $s16 = "function H(BuCmbVQyhGsJqy,JbWaDVYVJXUik,uaXJsOEHKij) {BuCmbVQyhGsJqy[JbWaDVYVJXUik]=uaXJsOEHKij;}" fullword ascii
    $s17 = "function QGABnvCzideW(XVJVCDAMBXLvM) {return isFinite(XVJVCDAMBXLvM);}" fullword ascii
    $s18 = "function VkcQUcoctAcyvrZuCKVfpsipLMVKaUkJJqJsqWgEJipPnbYeQOgJJJ(CMNpRDnoTskxR,aHkaWrnOxllFtM){ return WUFLnQM[EyWwsnLC[fzMAR(CMN" ascii
    $s19 = "function rudVwfL(fcNgCltAqvjfOuJAMVSWkyITffBETmLXzNLu) {return !DADOfDTlYpb(XFvLiQVPnNiCReE(fcNgCltAqvjfOuJAMVSWkyITffBETmLXzNLu" ascii
    $s20 = "function fzMAR(aiVsxFsmraK,hfbkdilQaqsXZ,GceyKjDA){UHoA=CZvuajsnghXSfkMEo(aiVsxFsmraK,hfbkdilQaqsXZ);DOMUd=UHoA.toString(GceyKjD" ascii

  condition:
    uint16(0) == 0x7945 and
    8 of them
}