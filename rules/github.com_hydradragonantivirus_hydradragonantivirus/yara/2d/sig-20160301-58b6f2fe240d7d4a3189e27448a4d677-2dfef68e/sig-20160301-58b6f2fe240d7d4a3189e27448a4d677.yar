rule sig_20160301_58b6f2fe240d7d4a3189e27448a4d677 {
  meta:
    description = "datamaliciousorder - file 20160301_58b6f2fe240d7d4a3189e27448a4d677.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e369bc8026e128d20334066bca642f4955c367f49066992f14e0e2c002d2c6d"

  strings:
    $s1  = "var Zn = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(XHFzg);" fullword ascii
    $s3  = "var OZK = (fas + \"TTP\" + \" XQXAIfF FFJHi XML ream St GuRPRvBf AD MdZgsqA OD\").split(\" \");" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + giNXHUh + \".F\" + ceJlcGYoRF + VcEpc + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var Ra = true  , vBlN = OZK[7] + \"\" + OZK[9];" fullword ascii
    $s6  = "function XUNw(ZTtmp,vapic) {" fullword ascii
    $s7  = "wRwJa.open(lMFUG,KyEJq,false);" fullword ascii
    $s8  = "if(t>=h.length) {break;}" fullword ascii
    $s9  = "function IiLf(wRwJa,KyEJq,lMFUG) {" fullword ascii
    $s10 = "function wdZN(dhZoj) {" fullword ascii
    $s11 = "if (pvEnU > 152961-533){return true;} else {return false;}" fullword ascii
    $s12 = "function Bukc(XHFzg) {" fullword ascii
    $s13 = "function URuOUIdzB(jmAjNOmEWvM) {" fullword ascii
    $s14 = "function Xrwt(pvEnU) {" fullword ascii
    $s15 = "return dMccY.status;" fullword ascii
    $s16 = "if (lSMHS == 1091-891){return true;} else {return false;}" fullword ascii
    $s17 = "function KmVc(yfTYE) {" fullword ascii
    $s18 = "function LVfT(lSMHS) {" fullword ascii
    $s19 = "return iBAuE;" fullword ascii
    $s20 = "if (((new Date())>0,7849785888)) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}