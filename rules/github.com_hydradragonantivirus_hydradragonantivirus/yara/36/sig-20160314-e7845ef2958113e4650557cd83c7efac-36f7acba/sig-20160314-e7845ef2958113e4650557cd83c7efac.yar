rule sig_20160314_e7845ef2958113e4650557cd83c7efac {
  meta:
    description = "datamaliciousorder - file 20160314_e7845ef2958113e4650557cd83c7efac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60cd4d55639b3d90c43b61019ada914b7d3df7130193eeeaa85a46d5878fb8e3"

  strings:
    $s1  = "return BkPsBtN[0] + BkPsBtN[2] + BkPsBtN[4] + \".F\" + BkPsBtN[7] + BkPsBtN[9] + BkPsBtN[12] + BkPsBtN[14];" fullword ascii
    $s2  = "var XF = true  , UYAd = Qll[7] + Qll[9] + Qll[11];" fullword ascii
    $s3  = "aBBmk.open(zRDPW,VfVTt,false);" fullword ascii
    $s4  = "var BkPsBtN = \"Sc GgVixdu r DWKKIaAXF ipting VbhegQt jSw ile TUFszoNZMWAHjG System eL KgpuY Obj kikpzC ect fhsGlwF GFvKj\".spli" ascii
    $s5  = "var Qll = (\"2.XMLHTTP KSrepQW NDwPd XML ream St aRhVXqYz AD OhuQAIR O jBFQ D\").split(\" \");" fullword ascii
    $s6  = "var BkPsBtN = \"Sc GgVixdu r DWKKIaAXF ipting VbhegQt jSw ile TUFszoNZMWAHjG System eL KgpuY Obj kikpzC ect fhsGlwF GFvKj\".spli" ascii
    $s7  = "if (xoFXB == 881-681){return true;} else {return false;}" fullword ascii
    $s8  = "function LUlQkwHJK() {" fullword ascii
    $s9  = "if (u >= DVvHn.length) {break;}" fullword ascii
    $s10 = "function Rrzr(Bodmn) {" fullword ascii
    $s11 = "var TD = zEsT(iI).split(\" \");" fullword ascii
    $s12 = "function mRWu(hXPJk,kbjTT) {" fullword ascii
    $s13 = "function yQiT(llkCz) {" fullword ascii
    $s14 = "function kLnY(AtAUZ) {" fullword ascii
    $s15 = "function DLvgm(CUfUkM) {" fullword ascii
    $s16 = "jQG = O; break; " fullword ascii
    $s17 = "if(O>=l.length) {break;}" fullword ascii
    $s18 = "function SnJL(vifiI) {" fullword ascii
    $s19 = "return Jyhy.responseBody;" fullword ascii
    $s20 = "function bQCMxHT(Jyhy) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}