rule sig_20160307_f89d1dd68526fd379287d4d0631819cc {
  meta:
    description = "datamaliciousorder - file 20160307_f89d1dd68526fd379287d4d0631819cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09193c094a03968d1ea28aca0124c37607abe407427e7cd71def997285aabbdd"

  strings:
    $s1  = "return mZoehvn[0] + mZoehvn[2] + mZoehvn[4] + \".F\" + mZoehvn[7] + mZoehvn[9] + mZoehvn[12] + mZoehvn[14];" fullword ascii
    $s2  = "var Ny = true  , kohc = ajW[7] + ajW[9] + ajW[11];" fullword ascii
    $s3  = "BcqvI.open(EZGKD,dXFgC,false);" fullword ascii
    $s4  = "var mZoehvn = \"Sc BgWGcvA r hvKSXTgQp ipting boMvVxo jGF ile ilGMEyPSqvhVTi System rt dEXGf Obj xFyGWX ect IbIBkWl\".split(\" " ascii
    $s5  = "var ajW = (\"2.XMLHTTP nyESiCX VLmlJ XML ream St vKErfGDY AD crwGoON O wRRs D\").split(\" \");" fullword ascii
    $s6  = "function OdslmmK(ChCl) {" fullword ascii
    $s7  = "return PZfDD;" fullword ascii
    $s8  = "BjE = c; break; " fullword ascii
    $s9  = "if (((new Date())>0,7636107888)) {" fullword ascii
    $s10 = "if (R >= onLKC.length) {break;}" fullword ascii
    $s11 = "function JhCqB(KuBrXo) {" fullword ascii
    $s12 = "function udefHcQf() {" fullword ascii
    $s13 = "return Qn.ExpandEnvironmentStrings(Knalo[6]+Knalo[7]+Knalo[8]);" fullword ascii
    $s14 = "function Dhod(jLhqc) {" fullword ascii
    $s15 = "function TEuL(BcqvI,dXFgC,EZGKD) {" fullword ascii
    $s16 = "function eEywSYuFB(zOcgPdQRzDv) {" fullword ascii
    $s17 = "if(c>=N.length) {break;}" fullword ascii
    $s18 = "function dBlt(ZUVDe) {" fullword ascii
    $s19 = "function fYhB(KZdbK) {" fullword ascii
    $s20 = "function wuan(YxWkw,nzuwb) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}