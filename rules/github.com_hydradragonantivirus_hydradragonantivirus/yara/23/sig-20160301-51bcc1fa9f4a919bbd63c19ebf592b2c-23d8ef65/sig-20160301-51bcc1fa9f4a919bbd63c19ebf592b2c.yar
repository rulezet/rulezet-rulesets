rule sig_20160301_51bcc1fa9f4a919bbd63c19ebf592b2c {
  meta:
    description = "datamaliciousorder - file 20160301_51bcc1fa9f4a919bbd63c19ebf592b2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c5c1406692459ed03061fa353555129f5ee2eff61e10d4f677c9feb115d38af"

  strings:
    $s1  = "var jo = \"%TEMP%\\\\\";" fullword ascii
    $s2  = "return WScript.CreateObject(prOJJ);" fullword ascii
    $s3  = "var Ii = true  , MiMZ = Ztl[7] + \"\" + Ztl[9];" fullword ascii
    $s4  = "return \"Sc\" + \"r\" + UuUOlJz + \".F\" + ZDFLFIOQBD + kXTIb + \"Obj\" + \"ect\";" fullword ascii
    $s5  = "var Ztl = (FqV + \"TTP\" + \" XOFkStA WXjPj XML ream St pZGxCEeH AD xgQXuRC OD\").split(\" \");" fullword ascii
    $s6  = "kKvKU.open(KbCkJ,sQFhi,false);" fullword ascii
    $s7  = "function RHAmmPCmb(mQfDRIUMeCu) {" fullword ascii
    $s8  = "function awqY(tGrEp) {" fullword ascii
    $s9  = "return BI.ExpandEnvironmentStrings(jo);" fullword ascii
    $s10 = "return new ActiveXObject(baPjsB);" fullword ascii
    $s11 = "if(c>=A.length) {break;}" fullword ascii
    $s12 = "function fJmy(prOJJ) {" fullword ascii
    $s13 = "function GiXy(fGKCg) {" fullword ascii
    $s14 = "function MeFc(kKvKU,sQFhi,KbCkJ) {" fullword ascii
    $s15 = "function Wezk(iYeNz,mhznN) {" fullword ascii
    $s16 = "function pOBfoVjI() {" fullword ascii
    $s17 = "function MHBlB(baPjsB) {" fullword ascii
    $s18 = "if (zgBkG == 1054-854){return true;} else {return false;}" fullword ascii
    $s19 = "return tcdfA;" fullword ascii
    $s20 = "return CGqhm.status;" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}