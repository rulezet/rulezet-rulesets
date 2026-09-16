rule sig_20160314_73dd1d8f19ced42cfe075a58b11480ac {
  meta:
    description = "datamaliciousorder - file 20160314_73dd1d8f19ced42cfe075a58b11480ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b497f3124ca769890d6d9091ceac1ff9d70ab9dbc8a6f976c16223b9c0ac300"

  strings:
    $s1  = "var lt = true  , pwMa = xoK[7] + xoK[9] + xoK[11];" fullword ascii
    $s2  = "return mZXnVoo[0] + mZXnVoo[2] + mZXnVoo[4] + \".F\" + mZXnVoo[7] + mZXnVoo[9] + mZXnVoo[12] + mZXnVoo[14];" fullword ascii
    $s3  = "var mZXnVoo = \"Sc gMLiwaw r pacyiMLmu ipting eeIeqQT gzt ile aUFNSwXqLSuxsX System mJ YTJTB Obj TtmfYg ect LCkrzua cjeQu\".spli" ascii
    $s4  = "var mZXnVoo = \"Sc gMLiwaw r pacyiMLmu ipting eeIeqQT gzt ile aUFNSwXqLSuxsX System mJ YTJTB Obj TtmfYg ect LCkrzua cjeQu\".spli" ascii
    $s5  = "DwMMD.open(fajAg,tEVRs,false);" fullword ascii
    $s6  = "var xoK = (\"2.XMLHTTP UdctNpz uuFLs XML ream St lFpLvScm AD fhrJcPs O XLgT D\").split(\" \");" fullword ascii
    $s7  = "function SmvO(SRLWV) {" fullword ascii
    $s8  = "function TODh(GaHaE) {" fullword ascii
    $s9  = "function wTgLpLIc(nQo) {" fullword ascii
    $s10 = "if (lneiW == 1093-893){return true;} else {return false;}" fullword ascii
    $s11 = "VZl = u; break; " fullword ascii
    $s12 = "function VKHlKJajM() {" fullword ascii
    $s13 = "return AcRORvQ" fullword ascii
    $s14 = "return GaHaE.status;" fullword ascii
    $s15 = "function QqLn(FmnnP) {" fullword ascii
    $s16 = "return new ActiveXObject(IgVvDK);" fullword ascii
    $s17 = "function YKkUg(YFpUvr) {" fullword ascii
    $s18 = "function oCmgRDEO() {" fullword ascii
    $s19 = "return iMgO.responseBody;" fullword ascii
    $s20 = "function zciL(ZVcdw) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}