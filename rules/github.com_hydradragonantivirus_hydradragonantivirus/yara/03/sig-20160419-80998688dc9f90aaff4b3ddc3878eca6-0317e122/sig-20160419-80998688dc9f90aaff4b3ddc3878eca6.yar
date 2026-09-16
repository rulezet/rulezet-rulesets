rule sig_20160419_80998688dc9f90aaff4b3ddc3878eca6 {
  meta:
    description = "datamaliciousorder - file 20160419_80998688dc9f90aaff4b3ddc3878eca6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bc42d12f2f76a31a5a2761bde9b937e7f8487f8874063bacca4a2603dbcd0d1"

  strings:
    $s1  = "var tG = true  , iQUL = yXZ[7] + yXZ[9] + yXZ[11];" fullword ascii
    $s2  = "return NlFKNHH[0] + NlFKNHH[2] + NlFKNHH[4] + \".F\" + NlFKNHH[7] + NlFKNHH[9] + NlFKNHH[12] + NlFKNHH[14];" fullword ascii
    $s3  = "pvyR.open(UrARB,AsaOV,false);" fullword ascii
    $s4  = "var yXZ = (\"2.XMLHTTP exJNziL EqKrb XML ream St HKHFvpLc AD ChfFAwF O lART D\").split(\" \");" fullword ascii
    $s5  = "function GxDPIU(NUySRwR) {" fullword ascii
    $s6  = "return iIZei.status;" fullword ascii
    $s7  = "Hcb = V; break; " fullword ascii
    $s8  = "return GIx[fgme[0]](oZtaf);" fullword ascii
    $s9  = "function rgsH(iIZei) {" fullword ascii
    $s10 = "return ArgDhfF;" fullword ascii
    $s11 = "return KyrNpuR(vR,MQrUjM+AqjPl[231-223]);" fullword ascii
    $s12 = "function KyrNpuR(khpf,JMbNK) {" fullword ascii
    $s13 = "return YgcYZn[ZVai[699-699]]=123-123;" fullword ascii
    $s14 = "function iEgn(bBXgZ) {" fullword ascii
    $s15 = "function TBjETazrM(OdYPKjAXJRs) {" fullword ascii
    $s16 = "function ZQdM(bmRAr) {" fullword ascii
    $s17 = "function MmxC(hVRet) {" fullword ascii
    $s18 = "function FoMZI(WzDPZx) {" fullword ascii
    $s19 = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s20 = "function xVgbyVZK(HDuf) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}