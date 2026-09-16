rule sig_20160321_bea73c046b0dc9821eaef8008bc69fbd {
  meta:
    description = "datamaliciousorder - file 20160321_bea73c046b0dc9821eaef8008bc69fbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7312a4d6da4747fb0d17917d0a495d6236826c3a3b061c3aaffbdefb778996d2"

  strings:
    $s1  = "return WScript.CreateObject(ddcoa);" fullword ascii
    $s2  = "return WUzInuT[0] + WUzInuT[2] + WUzInuT[4] + \".F\" + WUzInuT[7] + WUzInuT[9] + WUzInuT[12] + WUzInuT[14];" fullword ascii
    $s3  = "var OP = true  , SmXZ = LyK[7] + LyK[9] + LyK[11];" fullword ascii
    $s4  = "var LyK = (\"2.XMLHTTP PivBtvK LomHF XML ream St wytAnqwT AD AuMdthE O YvCx D\").split(\" \");" fullword ascii
    $s5  = "var WUzInuT = uRcmI(tUwPodMTtC+\" \"+\"System Bg rDpkx Obj CeDNNa ect ZXAKSPu OfgnA\", \" \");" fullword ascii
    $s6  = "OhNDh.open(qvZcN,nGWHI,false);" fullword ascii
    $s7  = "if(J>=S.length) {break;}" fullword ascii
    $s8  = "function Vxqhsvej(ZyGh) {" fullword ascii
    $s9  = "function SAdc(inpyF,EqZeH) {" fullword ascii
    $s10 = "function EuaCMGEg(PQT) {" fullword ascii
    $s11 = "return kQaT.ExpandEnvironmentStrings(DWkMq);" fullword ascii
    $s12 = "function SHhffqO(wPTl) {" fullword ascii
    $s13 = "function HCHP(aXbPF) {" fullword ascii
    $s14 = "function uRcmI(Jon,qBsrO) {" fullword ascii
    $s15 = "function Uoyl(OUVUI) {" fullword ascii
    $s16 = "function phDw(OhNDh,nGWHI,qvZcN) {" fullword ascii
    $s17 = "function WSXYONl(kQaT,DWkMq) {" fullword ascii
    $s18 = "return wPTl[BiicHL[0]];" fullword ascii
    $s19 = "return PQT.size;" fullword ascii
    $s20 = "function xvcg(ddcoa) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}