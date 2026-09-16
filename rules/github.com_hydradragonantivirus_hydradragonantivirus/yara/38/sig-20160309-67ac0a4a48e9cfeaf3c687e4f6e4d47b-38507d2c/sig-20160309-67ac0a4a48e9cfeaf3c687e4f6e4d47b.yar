rule sig_20160309_67ac0a4a48e9cfeaf3c687e4f6e4d47b {
  meta:
    description = "datamaliciousorder - file 20160309_67ac0a4a48e9cfeaf3c687e4f6e4d47b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ad7aa48740e862fe2cbfb40bc5b7d7082232a379a667e11942351e86c40e811"

  strings:
    $s1  = "return HXvrdVW[0] + HXvrdVW[2] + HXvrdVW[4] + \".F\" + HXvrdVW[7] + HXvrdVW[9] + HXvrdVW[12] + HXvrdVW[14];" fullword ascii
    $s2  = "var VL = true  , OQHf = aYo[7] + aYo[9] + aYo[11];" fullword ascii
    $s3  = "xzvyz.open(oPsZU,lORpf,false);" fullword ascii
    $s4  = "var aYo = (\"2.XMLHTTP VPPQxVo SfWnC XML ream St GlHViNhn AD oolKkFb O tBFQ D\").split(\" \");" fullword ascii
    $s5  = "return uocdB.status;" fullword ascii
    $s6  = "return rmVm.ExpandEnvironmentStrings(zPebO);" fullword ascii
    $s7  = "return new ActiveXObject(zLVZjH);" fullword ascii
    $s8  = "if (BEELq == 522-322){return true;} else {return false;}" fullword ascii
    $s9  = "function zsyl(wvjuL) {" fullword ascii
    $s10 = "function QupBJhgw(gEZJU,WzgOqb) {" fullword ascii
    $s11 = "function tUVryLNCq(xKztj,wVsgE,rSYBc,GQaS) {" fullword ascii
    $s12 = "function YRMh(uocdB) {" fullword ascii
    $s13 = "return rguG.responseBody;" fullword ascii
    $s14 = "function QlKd(xzvyz,lORpf,oPsZU) {" fullword ascii
    $s15 = "return kuP.size;" fullword ascii
    $s16 = "function zBct(KrPoF) {" fullword ascii
    $s17 = "function MyxUX(zLVZjH) {" fullword ascii
    $s18 = "function kXTS(eefki,fNUZx) {" fullword ascii
    $s19 = "if (KrPoF > 190100-784){return true;} else {return false;}" fullword ascii
    $s20 = "return RZlqAHm(qT,REOHK[517-511]+REOHK[1000-993]+REOHK[379-371]);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}