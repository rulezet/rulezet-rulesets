rule sig_20160411_6147abdd99658c52426f1db53b8e67b0 {
  meta:
    description = "datamaliciousorder - file 20160411_6147abdd99658c52426f1db53b8e67b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbce284b00457eb79fe2f985af9cfd1e6858ba6816ca70211a7ee0be26c9a9f3"

  strings:
    $s1  = "function Wxabw(TWL,HdGeT) {" fullword ascii
    $s2  = "return TWL[Dnuw[0]](HdGeT);" fullword ascii
    $s3  = "return GGwZpUW[0] + GGwZpUW[2] + GGwZpUW[4] + \".F\" + GGwZpUW[7] + GGwZpUW[9] + GGwZpUW[12] + GGwZpUW[14];" fullword ascii
    $s4  = "var ga = true  , wPIo = pLy[7] + pLy[9] + pLy[11];" fullword ascii
    $s5  = "zFZp.open(pvmjK,UFpvb,false);" fullword ascii
    $s6  = "var pLy = (\"2.XMLHTTP ebdzCfE zUuhu XML ream St UNbgYrzb AD ycNjmYR O RfdU D\").split(\" \");" fullword ascii
    $s7  = "eval(function(p,a,c,k,e,d){e=function(c){return c};if(!\"\".replace(/^/,String)){while(c--){d[c]=k[c]||c}k=[function(e){return d" ascii
    $s8  = "function PwuLZXY(fCcC,pqAtB) {" fullword ascii
    $s9  = "function CuKtHYYI(cXfD) {" fullword ascii
    $s10 = "KUt = u; break; " fullword ascii
    $s11 = "if (dIrVI > 151763-610){return true;} else {return false;}" fullword ascii
    $s12 = "function YcuJkZMmS(rvIdgrmimMy) {" fullword ascii
    $s13 = "function CwHZPbcGi(sXuFm) {" fullword ascii
    $s14 = "function Bczq(yuRnt,CQVBZ) {" fullword ascii
    $s15 = "if(u>=U.length) {break;}" fullword ascii
    $s16 = "function eoJWakk(cISo) {" fullword ascii
    $s17 = "return iFbyM.status;" fullword ascii
    $s18 = "if (OytYQ == 1094-894){return true;} else {return false;}" fullword ascii
    $s19 = "function VfHf(OytYQ) {" fullword ascii
    $s20 = "function DFkH(lGlWS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}