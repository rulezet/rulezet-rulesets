rule sig_20160305_dcc938929d0bdad0f8a7a228a77238fb {
  meta:
    description = "datamaliciousorder - file 20160305_dcc938929d0bdad0f8a7a228a77238fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0f1021512aadbb0a2e9ae3fa54b53222a649b161e40bcdf31f88a9d1e1a817a"

  strings:
    $s1  = "var lFWzX = \"ujmwuq sHF pt.Shell RzVAjTl Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "return otZcILZ[0] + otZcILZ[2] + otZcILZ[4] + \".F\" + otZcILZ[7] + otZcILZ[9] + otZcILZ[12] + otZcILZ[14];" fullword ascii
    $s3  = "var sqr = (wlF + \"TTP\" + \" lrXkKJY PIWdT XML ream St qButUECg AD YhGyHGA OD\").split(\" \");" fullword ascii
    $s4  = "var iX = true  , KTVf = sqr[7] + \"\" + sqr[9];" fullword ascii
    $s5  = "var otZcILZ = \"Sc wNKjTWD r WksEDRmhr ipting eXVnxcG RRQ ile GxmyvbmGxDggBp System Vi YeZsY Obj INdqxX ect ANKYMyi\".split(\" " ascii
    $s6  = "TBBqk.open(hYtqo,IMdaa,false);" fullword ascii
    $s7  = "PZk = o; break; " fullword ascii
    $s8  = "function GIqs(KFGhm) {" fullword ascii
    $s9  = "return new ActiveXObject(KRAlxG);" fullword ascii
    $s10 = "return iMYu.responseBody;" fullword ascii
    $s11 = "return MwWTCmR" fullword ascii
    $s12 = "function dYEu(lFOgC) {" fullword ascii
    $s13 = "function aRelIHK(iMYu) {" fullword ascii
    $s14 = "function eAItjpSmS(wOoxxJkFoTU) {" fullword ascii
    $s15 = "return KFGhm.status;" fullword ascii
    $s16 = "function kWsSBmOTC(VAWFz,EjKOH,fRWps) {" fullword ascii
    $s17 = "if(o>=U.length) {break;}" fullword ascii
    $s18 = "function xfrT(TBBqk,IMdaa,hYtqo) {" fullword ascii
    $s19 = "if (XWtGI > 150429-370){return true;} else {return false;}" fullword ascii
    $s20 = "function OOLj(pUkYu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}