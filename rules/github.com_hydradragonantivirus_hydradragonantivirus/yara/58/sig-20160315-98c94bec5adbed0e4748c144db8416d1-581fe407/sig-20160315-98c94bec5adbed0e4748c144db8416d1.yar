rule sig_20160315_98c94bec5adbed0e4748c144db8416d1 {
  meta:
    description = "datamaliciousorder - file 20160315_98c94bec5adbed0e4748c144db8416d1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "892658d97fbabce29302969b77018d174c2fbf91a5374769337b5f02a0e0b374"

  strings:
    $s1  = "return AvFamup[0] + AvFamup[2] + AvFamup[4] + \".F\" + AvFamup[7] + AvFamup[9] + AvFamup[12] + AvFamup[14];" fullword ascii
    $s2  = "var CI = true  , CTzM = TCp[7] + TCp[9] + TCp[11];" fullword ascii
    $s3  = "var AvFamup = AUPCn(\"Sc BqomHyM r AystYLSEs ipting BaLdhpb JvY ile bzsTVaKvcYZdrb System Qc BsYIj Obj viPqBK ect mIUsesb planF" ascii
    $s4  = "var AvFamup = AUPCn(\"Sc BqomHyM r AystYLSEs ipting BaLdhpb JvY ile bzsTVaKvcYZdrb System Qc BsYIj Obj viPqBK ect mIUsesb planF" ascii
    $s5  = "if(D>=e.length) {break;}" fullword ascii
    $s6  = "function iBPsy(KnNvuI) {" fullword ascii
    $s7  = "return XXBC.responseBody;" fullword ascii
    $s8  = "function gVPp(fQtYM) {" fullword ascii
    $s9  = "function EzIt(yykvm,clKFz) {" fullword ascii
    $s10 = "function NRRL(jHBgR,ccGis) {" fullword ascii
    $s11 = "return MRH.split(rkkwp);" fullword ascii
    $s12 = "return eNpun;" fullword ascii
    $s13 = "Pvw = D; break; " fullword ascii
    $s14 = "function wDshPlie(pkU) {" fullword ascii
    $s15 = "return new ActiveXObject(HNuzai);" fullword ascii
    $s16 = "function KFksf(HNuzai) {" fullword ascii
    $s17 = "function XpxKuVTFH(xdfjnKTWuWt) {" fullword ascii
    $s18 = "function WCDf(XRTmz) {" fullword ascii
    $s19 = "if (iIcBS == 377-177){return true;} else {return false;}" fullword ascii
    $s20 = "function AUPCn(MRH,rkkwp) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}