rule sig_20160404_c911a9aa69816877504a3de4a4094c88 {
  meta:
    description = "datamaliciousorder - file 20160404_c911a9aa69816877504a3de4a4094c88.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4da7d83da58abd04a702ecdb7336feb5eded4f7592041a0ca4f1bb2c058c318"

  strings:
    $s1  = "return EcTXdbH[0] + EcTXdbH[2] + EcTXdbH[4] + \".F\" + EcTXdbH[7] + EcTXdbH[9] + EcTXdbH[12] + EcTXdbH[14];" fullword ascii
    $s2  = "var dh = true  , NhFO = gWH[7] + gWH[9] + gWH[11];" fullword ascii
    $s3  = "QERO.open(SuXKR,OJOQp,false);" fullword ascii
    $s4  = "var gWH = (\"2.XMLHTTP OpWgUtz hLmbF XML ream St BVAkTxhJ AD fyBlZxx O EHfl D\").split(\" \");" fullword ascii
    $s5  = "var EcTXdbH = PbweS(gSHzixCZKc+\" \"+\"System Zf atjSH Obj rbfygD ect IRfdRik HuWno\", \" \");" fullword ascii
    $s6  = "if(c>=N.length) {break;}" fullword ascii
    $s7  = "return XDKD[QYfQTO[0]];" fullword ascii
    $s8  = "function zgEXA(Zewszm) {" fullword ascii
    $s9  = "function qfYT(JlzaU) {" fullword ascii
    $s10 = "function UcxdTvFo(VuXg) {" fullword ascii
    $s11 = "function xySKwbU(XDKD) {" fullword ascii
    $s12 = "return YmRvs;" fullword ascii
    $s13 = "if (b >= Nykwh.length) {break;}" fullword ascii
    $s14 = "function reRqg(TccGtE) {" fullword ascii
    $s15 = "function FEIK(djFvk) {" fullword ascii
    $s16 = "return AdkR;" fullword ascii
    $s17 = "function wlSCtoLGO(MHSyv) {" fullword ascii
    $s18 = "function qrbM(ZyyTQ) {" fullword ascii
    $s19 = "function iOYG(lmeII,QBvnT) {" fullword ascii
    $s20 = "function PbweS(Jit,VJRGV) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}