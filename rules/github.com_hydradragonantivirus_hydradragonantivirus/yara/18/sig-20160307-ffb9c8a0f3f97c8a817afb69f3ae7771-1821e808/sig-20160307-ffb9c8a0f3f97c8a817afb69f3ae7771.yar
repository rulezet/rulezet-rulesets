rule sig_20160307_ffb9c8a0f3f97c8a817afb69f3ae7771 {
  meta:
    description = "datamaliciousorder - file 20160307_ffb9c8a0f3f97c8a817afb69f3ae7771.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e1231f7760638aaec12a83da05f44e0db849155cffaf769c47212937f2c60be5"

  strings:
    $s1  = "return LmbVjYB[0] + LmbVjYB[2] + LmbVjYB[4] + \".F\" + LmbVjYB[7] + LmbVjYB[9] + LmbVjYB[12] + LmbVjYB[14];" fullword ascii
    $s2  = "var wF = true  , bRjB = Vjm[7] + Vjm[9] + Vjm[11];" fullword ascii
    $s3  = "var Vjm = (\"2.XMLHTTP mGTkyaN GFxsk XML ream St SmPwKGyX AD nDnyJYP O MITR D\").split(\" \");" fullword ascii
    $s4  = "rdoQq.open(DdzTl,dCXKH,false);" fullword ascii
    $s5  = "var LmbVjYB = \"Sc LyinfYs r XhuGvRLAI ipting tbwCKAk wGL ile aiRXQtBxvYysok System EU tSUcd Obj eDYrCv ect ruffiOX\".split(\" " ascii
    $s6  = "function ghEo(yGLMg,qjtDR) {" fullword ascii
    $s7  = "function IlwxXLix() {" fullword ascii
    $s8  = "return xuhjE;" fullword ascii
    $s9  = "function KYDG(okqlr) {" fullword ascii
    $s10 = "if (((new Date())>0,730319888)) {" fullword ascii
    $s11 = "function lTNzLex(NLsa) {" fullword ascii
    $s12 = "if (varGA > 170850-119){return true;} else {return false;}" fullword ascii
    $s13 = "function wvvH(Czigx) {" fullword ascii
    $s14 = "function LYeW(TRABr,LwAcI) {" fullword ascii
    $s15 = "return NLsa.responseBody;" fullword ascii
    $s16 = "return jKbrZyM" fullword ascii
    $s17 = "function MFAIX(dJUXVy) {" fullword ascii
    $s18 = "return vTX.size;" fullword ascii
    $s19 = "return Czigx.status;" fullword ascii
    $s20 = "function fUDe(varGA) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}