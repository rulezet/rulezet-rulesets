rule sig_20160311_c57a5c9bd7c2a9ddbbef7a33c2b3d965 {
  meta:
    description = "datamaliciousorder - file 20160311_c57a5c9bd7c2a9ddbbef7a33c2b3d965.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5555225c4ed81efffa963ee8fc7c9b6941eaecaf26081bb870b9fe52a9b706b9"

  strings:
    $s1  = "var Dl = true  , gNjs = pnm[7] + pnm[9] + pnm[11];" fullword ascii
    $s2  = "return vApZwaD[0] + vApZwaD[2] + vApZwaD[4] + \".F\" + vApZwaD[7] + vApZwaD[9] + vApZwaD[12] + vApZwaD[14];" fullword ascii
    $s3  = "var pnm = (\"2.XMLHTTP yWTYMml wNYYb XML ream St IYThGVlk AD WRefnal O xJgf D\").split(\" \");" fullword ascii
    $s4  = "var vApZwaD = \"Sc OGqRqdS r brdTWwoYV ipting AyKWjGm PUH ile IhorUfWrjJWJpB System kI xfuDR Obj mcZhWV ect wEeaMXB\".split(\" " ascii
    $s5  = "function gRbN(EVChe) {" fullword ascii
    $s6  = "if (YydsH > 130992-906){return true;} else {return false;}" fullword ascii
    $s7  = "return JseX.ExpandEnvironmentStrings(Vvluh);" fullword ascii
    $s8  = "function yJCK(FLSrz) {" fullword ascii
    $s9  = "return vtRosXa(OJ,ovpsQ[750-744]+ovpsQ[656-649]+ovpsQ[509-501]);" fullword ascii
    $s10 = "return UGrV.responseBody;" fullword ascii
    $s11 = "function hpGsjDwzZ() {" fullword ascii
    $s12 = "function lAXvZRFbd(VtXWDzRejDd) {" fullword ascii
    $s13 = "znC = N; break; " fullword ascii
    $s14 = "if(N>=o.length) {break;}" fullword ascii
    $s15 = "function rCVOX(JNowzU) {" fullword ascii
    $s16 = "function kqvXSmgL(SzL) {" fullword ascii
    $s17 = "return JNowzU.position=556-556;" fullword ascii
    $s18 = "function vuxB(mNwKL,ILUPW) {" fullword ascii
    $s19 = "return RcDEobH" fullword ascii
    $s20 = "if (t >= XAnBc.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}