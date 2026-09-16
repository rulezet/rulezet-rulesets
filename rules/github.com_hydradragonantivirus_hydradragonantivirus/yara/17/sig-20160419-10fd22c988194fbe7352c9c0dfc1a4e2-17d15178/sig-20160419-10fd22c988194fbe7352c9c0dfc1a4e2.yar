rule sig_20160419_10fd22c988194fbe7352c9c0dfc1a4e2 {
  meta:
    description = "datamaliciousorder - file 20160419_10fd22c988194fbe7352c9c0dfc1a4e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c459de2a833ffd8747aa63b623405e4a3ccc225c283c9e5fe370faf5f83a614"

  strings:
    $s1  = "var jm = true  , zzIJ = knq[7] + knq[9] + knq[11];" fullword ascii
    $s2  = "return AWktMUw[0] + AWktMUw[2] + AWktMUw[4] + \".F\" + AWktMUw[7] + AWktMUw[9] + AWktMUw[12] + AWktMUw[14];" fullword ascii
    $s3  = "qEkM.open(IFspN,FCnfy,false);" fullword ascii
    $s4  = "var knq = (\"2.XMLHTTP zZVGtTA FGelK XML ream St OYHOJTEt AD MDBiBnc O iDST D\").split(\" \");" fullword ascii
    $s5  = "function kmSaA(CMSrvP) {" fullword ascii
    $s6  = "VcF = K; break; " fullword ascii
    $s7  = "return VsRHo.status;" fullword ascii
    $s8  = "return vDnE[QKdHqvn[0]+QKdHqvn[1]];" fullword ascii
    $s9  = "function retMX(TFg,oxhyc) {" fullword ascii
    $s10 = "function jIAVRr(uPLS,qTnGmZ) {" fullword ascii
    $s11 = "function nUxdQjq(uHZr,LsKzq) {" fullword ascii
    $s12 = "if (g >= NFFZZ.length) {break;}" fullword ascii
    $s13 = "function acNymBBhp(WfNuUYbodnf) {" fullword ascii
    $s14 = "function qbxzxPaf(FuL) {" fullword ascii
    $s15 = "return new ActiveXObject(ZbGT);" fullword ascii
    $s16 = "return CMSrvP[HidO[325-325]]=755-755;" fullword ascii
    $s17 = "function klMHmuqff(pfkRj) {" fullword ascii
    $s18 = "function awwjlZB(vDnE) {" fullword ascii
    $s19 = "return FuL.size;" fullword ascii
    $s20 = "function yGof(cQMXc,FCnfy,IFspN) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}