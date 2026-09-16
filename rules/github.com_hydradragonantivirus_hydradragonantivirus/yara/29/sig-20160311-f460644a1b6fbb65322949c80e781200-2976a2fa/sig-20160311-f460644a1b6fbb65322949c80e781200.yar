rule sig_20160311_f460644a1b6fbb65322949c80e781200 {
  meta:
    description = "datamaliciousorder - file 20160311_f460644a1b6fbb65322949c80e781200.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "998ab2edf12c96e36b11c8828b9e518e91827df8e1567de25010936312d1588f"

  strings:
    $s1  = "function bzmoMwXMF(vfiHmMdeYej) {" fullword ascii
    $s2  = "var gn = true  , GOBr = HKc[7] + HKc[9] + HKc[11];" fullword ascii
    $s3  = "return KWEaVhS[0] + KWEaVhS[2] + KWEaVhS[4] + \".F\" + KWEaVhS[7] + KWEaVhS[9] + KWEaVhS[12] + KWEaVhS[14];" fullword ascii
    $s4  = "qRRGU.open(mNhzn,zaxZL,false);" fullword ascii
    $s5  = "var HKc = (\"2.XMLHTTP sRoKuyR oZroE XML ream St POsDRLuB AD dekHmmT O KGZS D\").split(\" \");" fullword ascii
    $s6  = "var KWEaVhS = \"Sc QYkxnLx r ThYyULKNc ipting CdEaUkE jRi ile dGTTxgRdrZtxoP System aX jusfo Obj oYInPL ect wezluIK\".split(\" " ascii
    $s7  = "function vpixqVJX(frn) {" fullword ascii
    $s8  = "function OPwpi(GwTeDT) {" fullword ascii
    $s9  = "function hNbY(vipCT) {" fullword ascii
    $s10 = "return GwTeDT.position=816-816;" fullword ascii
    $s11 = "function cGMt(GZbjm,dAoGZ) {" fullword ascii
    $s12 = "function FqzmgXdg(BQdMT,ilMleN) {" fullword ascii
    $s13 = "return AenY.ExpandEnvironmentStrings(IkPXy);" fullword ascii
    $s14 = "if (q >= vipCT.length) {break;}" fullword ascii
    $s15 = "function kHAKTmIQ() {" fullword ascii
    $s16 = "return hezIDcW" fullword ascii
    $s17 = "return Kmgs.responseBody;" fullword ascii
    $s18 = "function SIrPrck(Kmgs) {" fullword ascii
    $s19 = "return hxWdn.status;" fullword ascii
    $s20 = "hkX = d; break; " fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}