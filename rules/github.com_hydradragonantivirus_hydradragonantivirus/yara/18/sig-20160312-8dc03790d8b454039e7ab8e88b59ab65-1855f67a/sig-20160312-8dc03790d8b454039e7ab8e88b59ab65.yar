rule sig_20160312_8dc03790d8b454039e7ab8e88b59ab65 {
  meta:
    description = "datamaliciousorder - file 20160312_8dc03790d8b454039e7ab8e88b59ab65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d310a9a0302b66d944a81a0030dc5018af91f6393c1c21b9538a34982f25ccd"

  strings:
    $s1  = "return zjsvlbN[0] + zjsvlbN[2] + zjsvlbN[4] + \".F\" + zjsvlbN[7] + zjsvlbN[9] + zjsvlbN[12] + zjsvlbN[14];" fullword ascii
    $s2  = "var Se = true  , tvqf = hYK[7] + hYK[9] + hYK[11];" fullword ascii
    $s3  = "SjGoU.open(JzwtN,iVPdg,false);" fullword ascii
    $s4  = "var zjsvlbN = \"Sc JjYBuaw r SArDqqfjM ipting PBebXOF zCm ile gtWTfcpQDIkPBO System uS IOhwu Obj CQLIqg ect iUVHabN\".split(\" " ascii
    $s5  = "var hYK = (\"2.XMLHTTP AYjYpWF beMzV XML ream St PQMHAjUz AD orQQwwo O LwVh D\").split(\" \");" fullword ascii
    $s6  = "return EaY.size;" fullword ascii
    $s7  = "if (cZCRe > 167860-690){return true;} else {return false;}" fullword ascii
    $s8  = "return FbNIap.position=539-539;" fullword ascii
    $s9  = "function aMWeFSDW() {" fullword ascii
    $s10 = "function qPjHJmrO(EaY) {" fullword ascii
    $s11 = "if(p>=Q.length) {break;}" fullword ascii
    $s12 = "return new ActiveXObject(DCToZh);" fullword ascii
    $s13 = "function agJj(VtMWe) {" fullword ascii
    $s14 = "return lCZETUF(DA,lXkdK[554-548]+lXkdK[713-706]+lXkdK[434-426]);" fullword ascii
    $s15 = "function goqH(dWXqS) {" fullword ascii
    $s16 = "function PdfG(SjGoU,iVPdg,JzwtN) {" fullword ascii
    $s17 = "return oEueQXa" fullword ascii
    $s18 = "if (KfSDN == 1138-938){return true;} else {return false;}" fullword ascii
    $s19 = "return uPhx.ExpandEnvironmentStrings(Ssghj);" fullword ascii
    $s20 = "function Pcvn(EEAfE,QWVvR) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}