rule sig_20160308_18b714fb4bf1cdfd5a9ae6c28e0d822e {
  meta:
    description = "datamaliciousorder - file 20160308_18b714fb4bf1cdfd5a9ae6c28e0d822e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c0ea0629ab795ce38f1f7260c0de24a50f3654dfe883b4c701777a016a7963e"

  strings:
    $s1  = "var DE = true  , nhJi = bPy[7] + bPy[9] + bPy[11];" fullword ascii
    $s2  = "return CqRfulv[0] + CqRfulv[2] + CqRfulv[4] + \".F\" + CqRfulv[7] + CqRfulv[9] + CqRfulv[12] + CqRfulv[14];" fullword ascii
    $s3  = "var bPy = (\"2.XMLHTTP URWbJPq JIAeV XML ream St GXZWdGWq AD gEXIhfD O kOvs D\").split(\" \");" fullword ascii
    $s4  = "NvbfB.open(Cbzsz,wtGjL,false);" fullword ascii
    $s5  = "if(P>=Q.length) {break;}" fullword ascii
    $s6  = "function Cfpq(vGjwQ) {" fullword ascii
    $s7  = "if (((new Date())>0,7308323888)) {" fullword ascii
    $s8  = "function gLpD(WXdoi) {" fullword ascii
    $s9  = "function gvEJ(CVkGQ) {" fullword ascii
    $s10 = "function mrLIDXXM() {" fullword ascii
    $s11 = "return iFRdU;" fullword ascii
    $s12 = "return Qit.size;" fullword ascii
    $s13 = "if (WXdoi == 752-552){return true;} else {return false;}" fullword ascii
    $s14 = "function UMzCrKYfw(fSyfi,biXwr,rJArR,TQzH) {" fullword ascii
    $s15 = "function SXGe(pZdNC) {" fullword ascii
    $s16 = "function JEiN(NvbfB,wtGjL,Cbzsz) {" fullword ascii
    $s17 = "function Cdnn(lEZhx) {" fullword ascii
    $s18 = "function bows(DcCbQ,JhScd) {" fullword ascii
    $s19 = "function ckEnc(XTvJUP) {" fullword ascii
    $s20 = "function hDzl(XjqPY) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}