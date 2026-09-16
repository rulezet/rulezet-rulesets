rule sig_20160312_396df53652a345204658e89c4f58fe30 {
  meta:
    description = "datamaliciousorder - file 20160312_396df53652a345204658e89c4f58fe30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ad984e6c4f170c82de77d8e0cb3026ddfb86e3d51f1d7168085ddb8ca2aac66"

  strings:
    $s1  = "var rR = true  , Jmoz = KUF[7] + KUF[9] + KUF[11];" fullword ascii
    $s2  = "return IGrAbHf[0] + IGrAbHf[2] + IGrAbHf[4] + \".F\" + IGrAbHf[7] + IGrAbHf[9] + IGrAbHf[12] + IGrAbHf[14];" fullword ascii
    $s3  = "var KUF = (\"2.XMLHTTP NAxEsad Ferbx XML ream St weWaBiGY AD NxTOhxY O qlgQ D\").split(\" \");" fullword ascii
    $s4  = "IANZZ.open(LCWNT,FeowC,false);" fullword ascii
    $s5  = "var IGrAbHf = \"Sc twSTVcQ r ERGWQIgJi ipting MRYnRSK rFB ile zgkgWdyTybkPdu System PI FJGYL Obj JMWAak ect RSzqflQ\".split(\" " ascii
    $s6  = "if(H>=M.length) {break;}" fullword ascii
    $s7  = "if (Q >= spZrC.length) {break;}" fullword ascii
    $s8  = "function iMmkiLUz(eHY) {" fullword ascii
    $s9  = "function enYBb(EGAgds) {" fullword ascii
    $s10 = "return sooZ.responseBody;" fullword ascii
    $s11 = "function herI(RZPjl) {" fullword ascii
    $s12 = "return nuIOmme(Po,ffVVH[272-266]+ffVVH[936-929]+ffVVH[871-863]);" fullword ascii
    $s13 = "function CiyJv(wpbjlF) {" fullword ascii
    $s14 = "return vpsn.ExpandEnvironmentStrings(aYnNX);" fullword ascii
    $s15 = "function Oiqg(avAvo) {" fullword ascii
    $s16 = "return avAvo.status;" fullword ascii
    $s17 = "function vyUf(MiPXJ) {" fullword ascii
    $s18 = "return new ActiveXObject(EGAgds);" fullword ascii
    $s19 = "function nuIOmme(vpsn,aYnNX) {" fullword ascii
    $s20 = "function HRij(wwyJx,yrUzg) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}