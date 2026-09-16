rule sig_20160313_24deb26ec8bcb2f5d25d496b3562b80c {
  meta:
    description = "datamaliciousorder - file 20160313_24deb26ec8bcb2f5d25d496b3562b80c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1ef5435aa21824fc6b1d71fef0ee87907139c97358ffaceea5bfb473b7ce9520"

  strings:
    $s1  = "var Ck = true  , Cuxm = nJu[7] + nJu[9] + nJu[11];" fullword ascii
    $s2  = "return UisVNOv[0] + UisVNOv[2] + UisVNOv[4] + \".F\" + UisVNOv[7] + UisVNOv[9] + UisVNOv[12] + UisVNOv[14];" fullword ascii
    $s3  = "GnMrr.open(nBNQk,CmWOX,false);" fullword ascii
    $s4  = "var UisVNOv = \"Sc dNKUEmp r WvYgqONZz ipting zbxSLNB Pvw ile IXfwaBIjCfxQaT System pg nEkZi Obj pMPnjo ect lGtgZdj\".split(\" " ascii
    $s5  = "var nJu = (\"2.XMLHTTP PJdqfHw DKsTt XML ream St KzSbUiXJ AD kYYFDhr O KgyP D\").split(\" \");" fullword ascii
    $s6  = "if (A >= EyJUD.length) {break;}" fullword ascii
    $s7  = "function EYrd(NpxwH) {" fullword ascii
    $s8  = "if(p>=e.length) {break;}" fullword ascii
    $s9  = "function dpkUr(HDSHcU) {" fullword ascii
    $s10 = "function Iglh(EMTsN) {" fullword ascii
    $s11 = "function WkEo(WGMDH,iTYjS) {" fullword ascii
    $s12 = "return nJHvO;" fullword ascii
    $s13 = "function hryU(GnMrr,CmWOX,nBNQk) {" fullword ascii
    $s14 = "function QfokWTZEu(pVOtlxgJIdm) {" fullword ascii
    $s15 = "function dEti(lwXpi,CHxYO) {" fullword ascii
    $s16 = "if (OsDfJ > 183550-821){return true;} else {return false;}" fullword ascii
    $s17 = "return GEBbHGk(BE,CnVqs[369-363]+CnVqs[289-282]+CnVqs[661-653]);" fullword ascii
    $s18 = "return bByg.responseBody;" fullword ascii
    $s19 = "function pvzPfwh(bByg) {" fullword ascii
    $s20 = "return lWR.size;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}