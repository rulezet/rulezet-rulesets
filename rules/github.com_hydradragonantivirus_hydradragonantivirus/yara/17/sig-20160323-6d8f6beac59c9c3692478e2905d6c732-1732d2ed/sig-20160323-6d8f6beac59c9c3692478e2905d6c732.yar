rule sig_20160323_6d8f6beac59c9c3692478e2905d6c732 {
  meta:
    description = "datamaliciousorder - file 20160323_6d8f6beac59c9c3692478e2905d6c732.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d46e63a93798fcac3fb49481a0f02a4ff10fb1bebdac253cfe6bb69787439d8"

  strings:
    $s1  = "return WScript.CreateObject(NCYPa);" fullword ascii
    $s2  = "return xUNpRSX[0] + xUNpRSX[2] + xUNpRSX[4] + \".F\" + xUNpRSX[7] + xUNpRSX[9] + xUNpRSX[12] + xUNpRSX[14];" fullword ascii
    $s3  = "var jH = true  , pSVp = PGP[7] + PGP[9] + PGP[11];" fullword ascii
    $s4  = "var xUNpRSX = fpQbx(xBbhcbuIeO+\" \"+\"System mR jxSUS Obj FHaRPp ect Zeqwdrj Balws\", \" \");" fullword ascii
    $s5  = "hrRG.open(ohfGa,ryVbe,false);" fullword ascii
    $s6  = "var PGP = (\"2.XMLHTTP NiGlUOj gqNRp XML ream St qmHcmgOq AD hSlYKqu O PJdq D\").split(\" \");" fullword ascii
    $s7  = "oKM = f; break; " fullword ascii
    $s8  = "return AESYoEL(Cs,LdRNe[753-747]+LdRNe[670-663]+LdRNe[257-249]);" fullword ascii
    $s9  = "function AESYoEL(mkyS,LEzYd) {" fullword ascii
    $s10 = "function sBliRAEd(VFVY) {" fullword ascii
    $s11 = "function aqxD(rnskE,sOynx) {" fullword ascii
    $s12 = "function SyBD(IYjRw) {" fullword ascii
    $s13 = "function zgsL(yBFxH,ryVbe,ohfGa) {" fullword ascii
    $s14 = "if (i >= uwHQl.length) {break;}" fullword ascii
    $s15 = "if(f>=X.length) {break;}" fullword ascii
    $s16 = "function frox(NCYPa) {" fullword ascii
    $s17 = "return iPQF[wGMGXt[0]];" fullword ascii
    $s18 = "if (VlVaR > 197408-749){return true;} else {return false;}" fullword ascii
    $s19 = "return PLgouT/*mpyVq48lY5UVjuHhqUmHDv5RL*/.position=288-288;" fullword ascii
    $s20 = "function EFMl(hUJYz,ukYdW) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}