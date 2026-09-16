rule sig_20160411_3ef7a192157bc7d05c1883bb81cf9d98 {
  meta:
    description = "datamaliciousorder - file 20160411_3ef7a192157bc7d05c1883bb81cf9d98.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7871b241c175ae4a5e368866f784d686e6f6e77a5db03a443594063c2bf79929"

  strings:
    $s1  = "return djzrdcW[0] + djzrdcW[2] + djzrdcW[4] + \".F\" + djzrdcW[7] + djzrdcW[9] + djzrdcW[12] + djzrdcW[14];" fullword ascii
    $s2  = "var RV = true  , goJh = mWQ[7] + mWQ[9] + mWQ[11];" fullword ascii
    $s3  = "var mWQ = (\"2.XMLHTTP NqLfjOx FIAAy XML ream St yZUSCLXS AD rHsiAhm O vpnF D\").split(\" \");" fullword ascii
    $s4  = "return fKL.size;" fullword ascii
    $s5  = "if(P>=t.length) {break;}" fullword ascii
    $s6  = "function ivNu(YZyxL) {" fullword ascii
    $s7  = "return pqTBnox(wR,ocrqjy+Ctpgf[478-470]);" fullword ascii
    $s8  = "if (NJxZT > 165921-831){return true;} else {return false;}" fullword ascii
    $s9  = "function zHVx(EWffz) {" fullword ascii
    $s10 = "function MNxU(eieMw) {" fullword ascii
    $s11 = "function fKZh(huyLD) {" fullword ascii
    $s12 = "function hWtGTtA(VbUu) {" fullword ascii
    $s13 = "if (I >= hPefO.length) {break;}" fullword ascii
    $s14 = "function XLcqO(nXX,KNqip) {" fullword ascii
    $s15 = "function VJXCxm(ZesT,GYfalF) {" fullword ascii
    $s16 = "return new ActiveXObject(ySvw);" fullword ascii
    $s17 = "function pqTBnox(pTmY,GaTur) {" fullword ascii
    $s18 = "return czLaBph[0];" fullword ascii
    $s19 = "function pIFq(uzyyf) {" fullword ascii
    $s20 = "return bFPuV;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}