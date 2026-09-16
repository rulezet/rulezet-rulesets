rule sig_20160321_0cb5d64277cc5aa5201a9f6f28ccbe02 {
  meta:
    description = "datamaliciousorder - file 20160321_0cb5d64277cc5aa5201a9f6f28ccbe02.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa538395debb0e9d8b1bcd7f5eca595ba3503d69bcda0aa05cbada9c15576e8a"

  strings:
    $s1  = "return WScript.CreateObject(YLpwb);" fullword ascii
    $s2  = "return VpygYQf[0] + VpygYQf[2] + VpygYQf[4] + \".F\" + VpygYQf[7] + VpygYQf[9] + VpygYQf[12] + VpygYQf[14];" fullword ascii
    $s3  = "var xs = true  , Qxjz = wRq[7] + wRq[9] + wRq[11];" fullword ascii
    $s4  = "sUPhJ.open(xcCZP,LWWBd,false);" fullword ascii
    $s5  = "var VpygYQf = wJLfD(nBCDgCVtzS+\" \"+\"System dl VrchC Obj zPbRvP ect fVPpqgu XoAvZ\", \" \");" fullword ascii
    $s6  = "var wRq = (\"2.XMLHTTP PdJSPFN xUKkj XML ream St DMbmmeog AD KOAhgLT O pjtE D\").split(\" \");" fullword ascii
    $s7  = "function Unlc(yWEgr) {" fullword ascii
    $s8  = "return Cvd.split(SkxPn);" fullword ascii
    $s9  = "function xnpc(YLpwb) {" fullword ascii
    $s10 = "if(W>=Q.length) {break;}" fullword ascii
    $s11 = "function tinS(etDyd) {" fullword ascii
    $s12 = "smd = W; break; " fullword ascii
    $s13 = "return ZhTHr.status;" fullword ascii
    $s14 = "function wJLfD(Cvd,SkxPn) {" fullword ascii
    $s15 = "return XncV[WljgEq[0]];" fullword ascii
    $s16 = "function MsGG(ESMer,oaLZz) {" fullword ascii
    $s17 = "function Kpfn(sUPhJ,LWWBd,xcCZP) {" fullword ascii
    $s18 = "if (y >= eJuJw.length) {break;}" fullword ascii
    $s19 = "function cWoANqD(XncV) {" fullword ascii
    $s20 = "function yFby(eJuJw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}