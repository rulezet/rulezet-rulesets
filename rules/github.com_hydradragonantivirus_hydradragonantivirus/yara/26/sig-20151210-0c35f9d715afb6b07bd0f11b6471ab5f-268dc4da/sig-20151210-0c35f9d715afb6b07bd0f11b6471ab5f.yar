rule sig_20151210_0c35f9d715afb6b07bd0f11b6471ab5f {
  meta:
    description = "datamaliciousorder - file 20151210_0c35f9d715afb6b07bd0f11b6471ab5f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "941f3d95472149a284b00fb4d59404f9c7693d56835eaccfe6cfe988f4287f28"

  strings:
    $s1  = "function mzbEKJN(BbQItwzwBuMbvsBjzYatxDmRFgBqcxVkpgee) {return !isNaN(parseFloat(BbQItwzwBuMbvsBjzYatxDmRFgBqcxVkpgee)) && isFin" ascii
    $s2  = "function mzbEKJN(BbQItwzwBuMbvsBjzYatxDmRFgBqcxVkpgee) {return !isNaN(parseFloat(BbQItwzwBuMbvsBjzYatxDmRFgBqcxVkpgee)) && isFin" ascii
    $s3  = " bAiVB;}function taglvtXZJoLndRA(AVxaobLyqjVUMleRe){eval(AVxaobLyqjVUMleRe)}" fullword ascii
    $s4  = "function FduovePpMhl(qvVPTaAi,rjtiqo){return qvVPTaAi.split(rjtiqo)}" fullword ascii
    $s5  = "OacMGLXi[DnnSELtjCGj]=(-12+12)/749; while(true) { if(hOacMGLXi[DnnSELtjCGj] > LVZWV[DnnSELtjCGj].length-(101+686)/787) { break; " ascii
    $s6  = "function iwIxQOzawYltjjVIC(LVZWV){mpGEZmAAbYK= '';for(DnnSELtjCGj=(-856+856)/436; DnnSELtjCGj < (404+456)/430; DnnSELtjCGj++) {h" ascii
    $s7  = "function gkWRttbepsrWeCQeDunUkVFoGQqAaWSdwdBWYGooIulIjGodYOHGUj(IzewquBvBJPHu,KfMYVoyrzgndhG){ return huXll[cWTkf(IzewquBvBJPHu[" ascii
    $s8  = "function cWTkf(jFHciKKZGIr,CTnztzvZtgzfK,FVRieyuW){YXRB=parseInt(jFHciKKZGIr,CTnztzvZtgzfK);bAiVB=YXRB.toString(FVRieyuW);return" ascii
    $s9  = "} return mpGEZmAAbYK}" fullword ascii
    $s10 = "function iwIxQOzawYltjjVIC(LVZWV){mpGEZmAAbYK= '';for(DnnSELtjCGj=(-856+856)/436; DnnSELtjCGj < (404+456)/430; DnnSELtjCGj++) {h" ascii
    $s11 = "function gkWRttbepsrWeCQeDunUkVFoGQqAaWSdwdBWYGooIulIjGodYOHGUj(IzewquBvBJPHu,KfMYVoyrzgndhG){ return huXll[cWTkf(IzewquBvBJPHu[" ascii
    $s12 = "function cWTkf(jFHciKKZGIr,CTnztzvZtgzfK,FVRieyuW){YXRB=parseInt(jFHciKKZGIr,CTnztzvZtgzfK);bAiVB=YXRB.toString(FVRieyuW);return" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}