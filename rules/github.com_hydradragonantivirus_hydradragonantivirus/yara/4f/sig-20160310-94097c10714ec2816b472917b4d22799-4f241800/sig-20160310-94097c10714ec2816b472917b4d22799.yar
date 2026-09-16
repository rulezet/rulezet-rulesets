rule sig_20160310_94097c10714ec2816b472917b4d22799 {
  meta:
    description = "datamaliciousorder - file 20160310_94097c10714ec2816b472917b4d22799.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9865aade91bca2524d0a284270a6ceaaf985a4f32740fa2800640dc6c78f683e"

  strings:
    $s1  = "return ERkygGK[0] + ERkygGK[2] + ERkygGK[4] + \".F\" + ERkygGK[7] + ERkygGK[9] + ERkygGK[12] + ERkygGK[14];" fullword ascii
    $s2  = "var Qv = true  , FHCW = jKt[7] + jKt[9] + jKt[11];" fullword ascii
    $s3  = "VJnKM.open(wqSfW,fsJyj,false);" fullword ascii
    $s4  = "var jKt = (\"2.XMLHTTP rpizMCW AFgOM XML ream St fUFCileK AD HJDOFvo O zQHE D\").split(\" \");" fullword ascii
    $s5  = "function JSCg(MdHGQ) {" fullword ascii
    $s6  = "function Kxof(QwJUR,CPvnZ) {" fullword ascii
    $s7  = "return ReV.size;" fullword ascii
    $s8  = "function ppBPJLdHr(HuTkLLjTWHw) {" fullword ascii
    $s9  = "if (qtfsw == 794-594){return true;} else {return false;}" fullword ascii
    $s10 = "function JQeWY(JanzJN) {" fullword ascii
    $s11 = "function OjXX(Ywbhf) {" fullword ascii
    $s12 = "function BCDKXVrw() {" fullword ascii
    $s13 = "function vfkv(JvsrZ,SAbVI) {" fullword ascii
    $s14 = "function teCSNvB(SzKw,ygRjl) {" fullword ascii
    $s15 = "return new ActiveXObject(InBMmm);" fullword ascii
    $s16 = "function qcFz(VJnKM,fsJyj,wqSfW) {" fullword ascii
    $s17 = "return JanzJN.position=947-947;" fullword ascii
    $s18 = "return esXE.responseBody;" fullword ascii
    $s19 = "function twVo(LLDnx) {" fullword ascii
    $s20 = "if (lrjat > 177285-817){return true;} else {return false;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}