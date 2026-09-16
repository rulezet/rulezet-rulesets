rule sig_20160311_aabad9c8418bcff6f4434c412d6a6b50 {
  meta:
    description = "datamaliciousorder - file 20160311_aabad9c8418bcff6f4434c412d6a6b50.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6808c6140284075915129a40ae7db61a188d8432dfacd58557f84ffc5cdbf16c"

  strings:
    $s1  = "return oUSOwYs[0] + oUSOwYs[2] + oUSOwYs[4] + \".F\" + oUSOwYs[7] + oUSOwYs[9] + oUSOwYs[12] + oUSOwYs[14];" fullword ascii
    $s2  = "var NB = true  , Dkls = bvh[7] + bvh[9] + bvh[11];" fullword ascii
    $s3  = "var bvh = (\"2.XMLHTTP WasohND Qtezs XML ream St jOntJgiZ AD aJCUSRe O QPQZ D\").split(\" \");" fullword ascii
    $s4  = "jepAb.open(yTqVq,sZSsR,false);" fullword ascii
    $s5  = "if (e >= GmevI.length) {break;}" fullword ascii
    $s6  = "function jISoSHkQ() {" fullword ascii
    $s7  = "function TRjt(yjFPU) {" fullword ascii
    $s8  = "function IDOc(bNZhv,bIHCp) {" fullword ascii
    $s9  = "function KDtDfPzJP() {" fullword ascii
    $s10 = "return NtaK.responseBody;" fullword ascii
    $s11 = "if(Y>=u.length) {break;}" fullword ascii
    $s12 = "dMR = Y; break; " fullword ascii
    $s13 = "return ZNKCwJ.position=388-388;" fullword ascii
    $s14 = "return eflZq;" fullword ascii
    $s15 = "function SNIn(GmevI) {" fullword ascii
    $s16 = "if (bWNkV > 122815-449){return true;} else {return false;}" fullword ascii
    $s17 = "return AiaV.ExpandEnvironmentStrings(CoXxu);" fullword ascii
    $s18 = "function gTPhbweW(Brp) {" fullword ascii
    $s19 = "return HXVKT.status;" fullword ascii
    $s20 = "function TcZVnfF(AiaV,CoXxu) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}