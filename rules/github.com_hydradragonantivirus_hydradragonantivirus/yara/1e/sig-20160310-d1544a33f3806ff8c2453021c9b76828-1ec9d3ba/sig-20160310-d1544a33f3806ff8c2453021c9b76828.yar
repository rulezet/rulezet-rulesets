rule sig_20160310_d1544a33f3806ff8c2453021c9b76828 {
  meta:
    description = "datamaliciousorder - file 20160310_d1544a33f3806ff8c2453021c9b76828.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a744c8354feda97ae6bda541d86b6372417cc8bcf1e928919ad888d02761a1bb"

  strings:
    $s1  = "nnCMD.open(XNnvT,SAfGG,false);" fullword ascii
    $s2  = "return YVpjbWn[0] + YVpjbWn[2] + YVpjbWn[4] + \".F\" + YVpjbWn[7] + YVpjbWn[9] + YVpjbWn[12] + YVpjbWn[14];" fullword ascii
    $s3  = "var rd = true  , JHmG = ORm[7] + ORm[9] + ORm[11];" fullword ascii
    $s4  = "var YVpjbWn = \"Sc frRoaEd r cgqKFwGMA ipting SizDqer MjO ile eewBJIoLrJHMka System Zn niigq Obj cMtJtp ect BFpnbNZ\".split(\" " ascii
    $s5  = "var ORm = (\"2.XMLHTTP vkSBYPw Rrfmt XML ream St onXyrFiR AD VzIkqlg O hEUt D\").split(\" \");" fullword ascii
    $s6  = "function wKdD(nnCMD,SAfGG,XNnvT) {" fullword ascii
    $s7  = "function vEKo(GWFBF) {" fullword ascii
    $s8  = "function HQcd(GcRRE) {" fullword ascii
    $s9  = "function VcTntmz(gSTI) {" fullword ascii
    $s10 = "if(p>=l.length) {break;}" fullword ascii
    $s11 = "function eiaP(lBDiV) {" fullword ascii
    $s12 = "return zyqzvXX(Ci,WTNTk[174-168]+WTNTk[359-352]+WTNTk[210-202]);" fullword ascii
    $s13 = "return TyJg.ExpandEnvironmentStrings(cBPHq);" fullword ascii
    $s14 = "function Vlabg(QFxDgM) {" fullword ascii
    $s15 = "return new ActiveXObject(QFxDgM);" fullword ascii
    $s16 = "function oDgK(qzrSf,KpHMS) {" fullword ascii
    $s17 = "if (i >= AbiTr.length) {break;}" fullword ascii
    $s18 = "function eYQv(AbiTr) {" fullword ascii
    $s19 = "return GRJ.size;" fullword ascii
    $s20 = "function raHE(FmaPr) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}