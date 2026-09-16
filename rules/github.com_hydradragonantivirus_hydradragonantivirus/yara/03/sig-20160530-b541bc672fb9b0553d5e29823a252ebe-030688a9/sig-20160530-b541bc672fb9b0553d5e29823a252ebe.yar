rule sig_20160530_b541bc672fb9b0553d5e29823a252ebe {
  meta:
    description = "datamaliciousorder - file 20160530_b541bc672fb9b0553d5e29823a252ebe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8bc6446d6deff8b5d242c899d5450acc37dbe6e3bf23609f4ef65e5e6baf6e0"

  strings:
    $s1  = "var dkjUVSzEDtTd=function(){return WScript.CreateObject(OlyCvjglEMmykIaUZaMzqW[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function OAAgCdFa(SwXpLrCZkLmat) {var fBgUfHNchSok = iPlynEgEEGphr.join(OlyCvjglEMmykIaUZaMzqW[7]);var CYCSRUBX, eirILCrR, avRfd" ascii
    $s3  = "function kwfmAYwbsrFBvfj(HfdFnSMLTWWjsBzezLzWiWU,DCGZlKzvkk){return HfdFnSMLTWWjsBzezLzWiWU.charAt(DCGZlKzvkk);}" fullword ascii
    $s4  = "function pmHXvzWJMdZz(gWSGseSqlt,DzrgiaKJyUul) {var NOFacdtjmFsk=[OlyCvjglEMmykIaUZaMzqW[15]];gWSGseSqlt[NOFacdtjmFsk[0]]" fullword ascii
    $s5  = "function OAAgCdFa(SwXpLrCZkLmat) {var fBgUfHNchSok = iPlynEgEEGphr.join(OlyCvjglEMmykIaUZaMzqW[7]);var CYCSRUBX, eirILCrR, avRfd" ascii
    $s6  = "function RiEgsoLVdua(uSqTlMyvcBqR,jVbUtdm,QnXQlWzGPbbe){OeZLcYeKNxANeA=uSqTlMyvcBqR.split(QnXQlWzGPbbe);GMYTQB = OlyCvjglEMmykIa" ascii
    $s7  = "function aNQaeeETAN(){return RiEgsoLVdua(OlyCvjglEMmykIaUZaMzqW[13],[0,3,6],OlyCvjglEMmykIaUZaMzqW[14]);}" fullword ascii
    $s8  = "function GqOSVEp(){return RiEgsoLVdua(OlyCvjglEMmykIaUZaMzqW[11],[2,4,8,10],OlyCvjglEMmykIaUZaMzqW[12]);}" fullword ascii
    $s9  = "function qEfFDjJOG(jEVGONONAXfL,YuVBJHnhRljycOjnQfKll){return String.fromCharCode(jEVGONONAXfL,YuVBJHnhRljycOjnQfKll);}" fullword ascii
    $s10 = "ZJsskgpAgYVnwpd += CG(CYCSRUBX);else if (jVYByoyEuxCCWDIEL == 64) XbVrZJsskgpAgYVnwpd += qEfFDjJOG(CYCSRUBX, eirILCrR);else XbVr" ascii
    $s11 = "function SjjmBmVxrgQngUYKZVL(DqDQsKLansyDxoAMXsJU,QfTyZmZEpfxrWWViCtWvhlz){return DqDQsKLansyDxoAMXsJU.indexOf(QfTyZmZEpfxrWWViC" ascii
    $s12 = "function RiEgsoLVdua(uSqTlMyvcBqR,jVbUtdm,QnXQlWzGPbbe){OeZLcYeKNxANeA=uSqTlMyvcBqR.split(QnXQlWzGPbbe);GMYTQB = OlyCvjglEMmykIa" ascii
    $s13 = "function RXSisHm(aWcKKIYtY,VWAvGjVe,vBquDztFJ){return String.fromCharCode(aWcKKIYtY,VWAvGjVe,vBquDztFJ);}" fullword ascii
    $s14 = ")+String.fromCharCode(92)+OlyCvjglEMmykIaUZaMzqW[5],true);" fullword ascii
    $s15 = "ZJsskgpAgYVnwpd += RXSisHm(CYCSRUBX, eirILCrR, avRfdOsjznsFkrIFZIq);} while (pghtLAVlfd < SwXpLrCZkLmat.length);return XbVrZJssk" ascii
    $s16 = "function SjjmBmVxrgQngUYKZVL(DqDQsKLansyDxoAMXsJU,QfTyZmZEpfxrWWViCtWvhlz){return DqDQsKLansyDxoAMXsJU.indexOf(QfTyZmZEpfxrWWViC" ascii
    $s17 = "var cUTbQVZBtg=function(){return new ActiveXObject(OlyCvjglEMmykIaUZaMzqW[1]);}();" fullword ascii
    $s18 = "var MlzxUm = cUTbQVZBtg.createtextfile(dkjUVSzEDtTd.ExpandEnvironmentStrings(OlyCvjglEMmykIaUZaMzqW[3]+OlyCvjglEMmykIaUZaMzqW[4]" ascii
    $s19 = "UZaMzqW[0];for(YuhGpN=0;YuhGpN<jVbUtdm.length;YuhGpN++) {GMYTQB+=OeZLcYeKNxANeA[jVbUtdm[YuhGpN]];}return GMYTQB.substring(3,GMYT" ascii
    $s20 = "function oyqjioEui(){return RiEgsoLVdua(OlyCvjglEMmykIaUZaMzqW[9],[1,5,7],OlyCvjglEMmykIaUZaMzqW[10]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}