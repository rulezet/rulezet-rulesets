rule sig_20160309_64638340ad710202877151472e9aff44 {
  meta:
    description = "datamaliciousorder - file 20160309_64638340ad710202877151472e9aff44.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60b95f1571f847672b0c8d8f356b83d243d5be7473e9abecbf244dac25e4bd22"

  strings:
    $s1  = "return yMhoExb[0] + yMhoExb[2] + yMhoExb[4] + \".F\" + yMhoExb[7] + yMhoExb[9] + yMhoExb[12] + yMhoExb[14];" fullword ascii
    $s2  = "var OS = true  , nWkw = CjG[7] + CjG[9] + CjG[11];" fullword ascii
    $s3  = "var yMhoExb = \"Sc YELrlIR r cRaPksfOJ ipting zmasCkz Bqj ile GBpCSRyxkEhNpy System Zu NhlLb Obj kNIhBb ect DoCXsuE\".split(\" " ascii
    $s4  = "lGTLL.open(vZsnR,BNxDk,false);" fullword ascii
    $s5  = "function jtKEVRqd(OoBms,bkQZGY) {" fullword ascii
    $s6  = "WyT = c; break; " fullword ascii
    $s7  = "function nSKK(fgzri,QZKvS) {" fullword ascii
    $s8  = "function Vnvn(IESoY) {" fullword ascii
    $s9  = "function bKWZ(qRoqu,XJPsQ) {" fullword ascii
    $s10 = "function Obzvvva(mHod,GBtKT) {" fullword ascii
    $s11 = "function hgmY(umigX) {" fullword ascii
    $s12 = "function aUFl(kqJcg) {" fullword ascii
    $s13 = "function hSIf(olCWX) {" fullword ascii
    $s14 = "if (s >= olCWX.length) {break;}" fullword ascii
    $s15 = "return EwLHgsR" fullword ascii
    $s16 = "return mkXSV;" fullword ascii
    $s17 = "function aqbQ(qNzlO) {" fullword ascii
    $s18 = "if (RCwDa > 151173-668){return true;} else {return false;}" fullword ascii
    $s19 = "if (qNzlO == 509-309){return true;} else {return false;}" fullword ascii
    $s20 = "function yjzUjCX(phZE) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}