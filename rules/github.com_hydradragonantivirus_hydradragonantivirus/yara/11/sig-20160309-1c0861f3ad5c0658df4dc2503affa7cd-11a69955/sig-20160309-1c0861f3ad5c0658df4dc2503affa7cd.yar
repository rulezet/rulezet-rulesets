rule sig_20160309_1c0861f3ad5c0658df4dc2503affa7cd {
  meta:
    description = "datamaliciousorder - file 20160309_1c0861f3ad5c0658df4dc2503affa7cd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ce32ad6f1d95730d3f53b154b3969e9bc03ebde18bc7b96e1bb7dc41892531f"

  strings:
    $s1  = "var Pc = true  , KumQ = rNq[7] + rNq[9] + rNq[11];" fullword ascii
    $s2  = "return tWJKPRc[0] + tWJKPRc[2] + tWJKPRc[4] + \".F\" + tWJKPRc[7] + tWJKPRc[9] + tWJKPRc[12] + tWJKPRc[14];" fullword ascii
    $s3  = "var tWJKPRc = \"Sc RNbYMMb r cKhoWZLtW ipting cEeMrmB ziZ ile hOcZuICRokXWvJ System As xTfDk Obj ALHOpA ect GiVhkOT\".split(\" " ascii
    $s4  = "var rNq = (\"2.XMLHTTP WKjDRrS hDrJd XML ream St KHdciUTN AD qrDxkYo O emgQ D\").split(\" \");" fullword ascii
    $s5  = "return BGlEkdo(wF,zgsgw[291-285]+zgsgw[868-861]+zgsgw[683-675]);" fullword ascii
    $s6  = "function IbNG(WUPRT) {" fullword ascii
    $s7  = "function BGlEkdo(geZu,iIYul) {" fullword ascii
    $s8  = "if (WUPRT > 161836-802){return true;} else {return false;}" fullword ascii
    $s9  = "function LIFHQHt(pkEA) {" fullword ascii
    $s10 = "GLO = z; break; " fullword ascii
    $s11 = "function Bzxg(EYqLZ) {" fullword ascii
    $s12 = "if (EYqLZ == 362-162){return true;} else {return false;}" fullword ascii
    $s13 = "function qPBY(VmkPm) {" fullword ascii
    $s14 = "if(z>=l.length) {break;}" fullword ascii
    $s15 = "return edp.size;" fullword ascii
    $s16 = "return pkEA.responseBody;" fullword ascii
    $s17 = "function imqtnSAj(edp) {" fullword ascii
    $s18 = "function EZeH(imvzl) {" fullword ascii
    $s19 = "function ZgHdiXmGS(hAGpCtquvjh) {" fullword ascii
    $s20 = "function EUzC(UKlOl) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}