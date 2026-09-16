rule sig_20160307_61bb049710dd5e7bdfe8ca591c95ed26 {
  meta:
    description = "datamaliciousorder - file 20160307_61bb049710dd5e7bdfe8ca591c95ed26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea0e1e470fab99cc5a321df3047aade746fc481b01dda4c0d6da876a417e5ad"

  strings:
    $s1  = "var vh = true  , eMiU = UtQ[7] + UtQ[9] + UtQ[11];" fullword ascii
    $s2  = "return gQtDChC[0] + gQtDChC[2] + gQtDChC[4] + \".F\" + gQtDChC[7] + gQtDChC[9] + gQtDChC[12] + gQtDChC[14];" fullword ascii
    $s3  = "var UtQ = (\"2.XMLHTTP NfvxWJj gHsYV XML ream St dfwCkRbJ AD NUKmmIZ O OLSC D\").split(\" \");" fullword ascii
    $s4  = "xOCOT.open(eCTse,ECFFI,false);" fullword ascii
    $s5  = "function CsRl(qPfkw) {" fullword ascii
    $s6  = "return poZs.responseBody;" fullword ascii
    $s7  = "if(b>=u.length) {break;}" fullword ascii
    $s8  = "if (((new Date())>0,7920440888)) {" fullword ascii
    $s9  = "function KlGk(vOKdD,TcpOz) {" fullword ascii
    $s10 = "return iY.ExpandEnvironmentStrings(RqyIo[6]+RqyIo[7]+RqyIo[8]);" fullword ascii
    $s11 = "function MyuMIFjS(djW) {" fullword ascii
    $s12 = "function SzFDttX(poZs) {" fullword ascii
    $s13 = "function HJSp(iedBl) {" fullword ascii
    $s14 = "function VKxK(AbjeV,wIWSu) {" fullword ascii
    $s15 = "function FLaQ(sFBnB) {" fullword ascii
    $s16 = "function gfJB(gWitg) {" fullword ascii
    $s17 = "function rTLRTdC(CgzH) {" fullword ascii
    $s18 = "function QMpXQdppO(bgQWr,dOxaa,lQtcd,YRTn) {" fullword ascii
    $s19 = "function ptcre(fxhGFw) {" fullword ascii
    $s20 = "return new ActiveXObject(fxhGFw);" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}