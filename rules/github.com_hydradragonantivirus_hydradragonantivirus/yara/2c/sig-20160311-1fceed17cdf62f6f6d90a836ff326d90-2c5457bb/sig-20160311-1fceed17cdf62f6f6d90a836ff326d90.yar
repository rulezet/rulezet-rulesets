rule sig_20160311_1fceed17cdf62f6f6d90a836ff326d90 {
  meta:
    description = "datamaliciousorder - file 20160311_1fceed17cdf62f6f6d90a836ff326d90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b92aa998fe6fe5667bd5418ee1f7773bc4d9634d9fcff440ab78e66d6c58d036"

  strings:
    $s1  = "var ck = true  , hexZ = wMH[7] + wMH[9] + wMH[11];" fullword ascii
    $s2  = "return PkgIEZF[0] + PkgIEZF[2] + PkgIEZF[4] + \".F\" + PkgIEZF[7] + PkgIEZF[9] + PkgIEZF[12] + PkgIEZF[14];" fullword ascii
    $s3  = "function rRuN(CYtAt,HOAsT) {" fullword ascii
    $s4  = "var wMH = (\"2.XMLHTTP WkpnrRR FFAYe XML ream St AEiiUdbv AD ZfDpEjU O ZlZH D\").split(\" \");" fullword ascii
    $s5  = "XzokK.open(awwnz,EVcsG,false);" fullword ascii
    $s6  = "var PkgIEZF = \"Sc sagJbxR r cZQFgGJgq ipting DHqbOwU hbq ile EqubYJgZIBGMvZ System Wy nLlHj Obj bdxtvG ect ryHGYdL\".split(\" " ascii
    $s7  = "return RRMk.ExpandEnvironmentStrings(WgOxi);" fullword ascii
    $s8  = "return mmN.size;" fullword ascii
    $s9  = "function tHFi(HShzu) {" fullword ascii
    $s10 = "function YnSp(Jhwmc,PdrOB) {" fullword ascii
    $s11 = "if (HShzu == 323-123){return true;} else {return false;}" fullword ascii
    $s12 = "if (LcRrz > 132274-448){return true;} else {return false;}" fullword ascii
    $s13 = "function BJOg(BoNMx) {" fullword ascii
    $s14 = "function JTheQlmR(mmN) {" fullword ascii
    $s15 = "function hBtnRigQo() {" fullword ascii
    $s16 = "function GAlm(LcRrz) {" fullword ascii
    $s17 = "return sgXrvp.position=595-595;" fullword ascii
    $s18 = "function jcIC(ZTxTY) {" fullword ascii
    $s19 = "return XrAbIQk(Md,ABITo[609-603]+ABITo[446-439]+ABITo[903-895]);" fullword ascii
    $s20 = "return LhszK;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}