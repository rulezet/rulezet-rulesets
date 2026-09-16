rule sig_20160323_037193ef398385658fb8de49dabc91ef {
  meta:
    description = "datamaliciousorder - file 20160323_037193ef398385658fb8de49dabc91ef.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d614db2b34fd27859e5137e0b6a805be2db7b74d9e91dc19d3b7a02c6e6cbee6"

  strings:
    $s1  = "return WScript.CreateObject(alGlY);" fullword ascii
    $s2  = "return fQycFdR[0] + fQycFdR[2] + fQycFdR[4] + \".F\" + fQycFdR[7] + fQycFdR[9] + fQycFdR[12] + fQycFdR[14];" fullword ascii
    $s3  = "var WL = true  , SEuo = ICf[7] + ICf[9] + ICf[11];" fullword ascii
    $s4  = "hnfl.open(yfOYr,iJoiD,false);" fullword ascii
    $s5  = "var ICf = (\"2.XMLHTTP wVWECuV NGvQh XML ream St eewECWcg AD wiLXxmN O IXya D\").split(\" \");" fullword ascii
    $s6  = "if(M>=A.length) {break;}" fullword ascii
    $s7  = "if (L >= MIwWH.length) {break;}" fullword ascii
    $s8  = "return cUm.split(kIriP);" fullword ascii
    $s9  = "return ZIXWAFf(ma,IeGIS[899-893]+IeGIS[143-136]+IeGIS[790-782]);" fullword ascii
    $s10 = "return yykTL;" fullword ascii
    $s11 = "function EEffUxp(AsWE) {" fullword ascii
    $s12 = "if (JZeIb > 191466-317){return true;} else {return false;}" fullword ascii
    $s13 = "function wvvp(CZUDH,iJoiD,yfOYr) {" fullword ascii
    $s14 = "return QLaz.ExpandEnvironmentStrings(OhwCr);" fullword ascii
    $s15 = "if (QgBDq == 634-434){return true;} else {return false;}" fullword ascii
    $s16 = "return ltFBn.status;" fullword ascii
    $s17 = "function ZADIMyIz(vRb) {" fullword ascii
    $s18 = "return nllSGn/*cWpac8fnr0swOJNJymoMSTNRO*/.position=182-182;" fullword ascii
    $s19 = "function ZIXWAFf(QLaz,OhwCr) {" fullword ascii
    $s20 = "function goXS(PhaPp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}