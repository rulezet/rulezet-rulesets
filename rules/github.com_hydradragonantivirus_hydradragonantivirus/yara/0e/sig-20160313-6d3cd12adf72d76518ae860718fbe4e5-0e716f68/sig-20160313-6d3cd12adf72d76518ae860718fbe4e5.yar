rule sig_20160313_6d3cd12adf72d76518ae860718fbe4e5 {
  meta:
    description = "datamaliciousorder - file 20160313_6d3cd12adf72d76518ae860718fbe4e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f71ce859558933cdb118f1cde821270dc124d9bf5adcd0f50bdcb01e81157fbe"

  strings:
    $s1  = "var PS = true  , ithH = CKH[7] + CKH[9] + CKH[11];" fullword ascii
    $s2  = "return VqjhZFD[0] + VqjhZFD[2] + VqjhZFD[4] + \".F\" + VqjhZFD[7] + VqjhZFD[9] + VqjhZFD[12] + VqjhZFD[14];" fullword ascii
    $s3  = "var VqjhZFD = \"Sc uZVDbLh r RgVPBopmi ipting CucIcJg qcI ile bVHQhsokYNnfjN System mD uSjTK Obj vyWJsW ect PWeofUI\".split(\" " ascii
    $s4  = "var CKH = (\"2.XMLHTTP uVqZpnc iiqwu XML ream St FeHHpWaN AD lqsytAG O VWAF D\").split(\" \");" fullword ascii
    $s5  = "ezeSz.open(mZwpQ,mgopG,false);" fullword ascii
    $s6  = "if(c>=p.length) {break;}" fullword ascii
    $s7  = "function HvvFvyKPB() {" fullword ascii
    $s8  = "return adkXiXy(jO,VHgGQ[267-261]+VHgGQ[415-408]+VHgGQ[736-728]);" fullword ascii
    $s9  = "return CgqB.ExpandEnvironmentStrings(kHiYb);" fullword ascii
    $s10 = "function vazZR(XqKNtx) {" fullword ascii
    $s11 = "function tcGPiRQJC(jqkUadfzXTb) {" fullword ascii
    $s12 = "return RZZ.size;" fullword ascii
    $s13 = "if (jhpSX > 155371-331){return true;} else {return false;}" fullword ascii
    $s14 = "function kDpV(lxZhQ,JNSda) {" fullword ascii
    $s15 = "function jrbYBLJs(RZZ) {" fullword ascii
    $s16 = "function xYWe(ggIjm) {" fullword ascii
    $s17 = "return vVLTS;" fullword ascii
    $s18 = "function nbMC(JbPHw,ZnfSx) {" fullword ascii
    $s19 = "function qwGq(dBJhh) {" fullword ascii
    $s20 = "function xLDOtbi(JjyH) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}