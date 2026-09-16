rule sig_20160303_00e0d135a57f47aff2f69e4dbfaf9a54 {
  meta:
    description = "datamaliciousorder - file 20160303_00e0d135a57f47aff2f69e4dbfaf9a54.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9924b2ad2f9d47c7cb7cf2370697a0cf7968418d0d153b704091d9432c9e79d"

  strings:
    $s1  = "var lYjSe = \"yYkVCb SLY pt.Shell CURQMaK Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var PO = true  , MHJK = Otc[7] + \"\" + Otc[9];" fullword ascii
    $s3  = "return vmNuMTz[0] + vmNuMTz[2] + vmNuMTz[4] + \".F\" + vmNuMTz[7] + vmNuMTz[9] + vmNuMTz[12] + vmNuMTz[14];" fullword ascii
    $s4  = "var Otc = (gLj + \"TTP\" + \" qSNeMkO ckzes XML ream St CemRZSug AD VaIAtBh OD\").split(\" \");" fullword ascii
    $s5  = "wSjAu.open(YRKxr,pqBed,false);" fullword ascii
    $s6  = "var vmNuMTz = \"Sc lYQfkgY r HktZmkIti ipting IouLRCH Hki ile SYLXfvUFjrYoFU System Jp RBMlh Obj FokGgF ect cjsKVGt\".split(\" " ascii
    $s7  = "function uWLrvbn(cMDO) {" fullword ascii
    $s8  = "return cMDO.responseBody;" fullword ascii
    $s9  = "return new ActiveXObject(UFkuRY);" fullword ascii
    $s10 = "if (glXko == 904-704){return true;} else {return false;}" fullword ascii
    $s11 = "function oldq(wzEHJ,KuPud) {" fullword ascii
    $s12 = "function kmAnwTKcb(iIHXP,dwAYp,uGLxx) {" fullword ascii
    $s13 = "function svHnJnuRt(lKNDeLBCgpv) {" fullword ascii
    $s14 = "function NtHcPtA(enMv) {" fullword ascii
    $s15 = "function AIFabHdN() {" fullword ascii
    $s16 = "GAg = Z; break; " fullword ascii
    $s17 = "function SFaQ(KoRox,fXERP) {" fullword ascii
    $s18 = "if(Z>=k.length) {break;}" fullword ascii
    $s19 = "function sETt(glXko) {" fullword ascii
    $s20 = "return hDiDX.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}