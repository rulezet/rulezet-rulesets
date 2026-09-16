rule sig_20160303_14be39810eb1390a02df9fb98ea575ae {
  meta:
    description = "datamaliciousorder - file 20160303_14be39810eb1390a02df9fb98ea575ae.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26dc4567911afe80a56c261c9a8a7a5522004cdc87fea743e4f45127758f5da0"

  strings:
    $s1  = "var mfLSw = \"wNHmIx DvT pt.Shell bNiNZAi Scri  %TEMP%\\\\\".split(\" \");" fullword ascii
    $s2  = "var baR = (Kfv + \"TTP\" + \" aKLHxme PKjjk XML ream St ANZXARxQ AD SwzdCvy OD\").split(\" \");" fullword ascii
    $s3  = "var ft = true  , ksDy = baR[7] + \"\" + baR[9];" fullword ascii
    $s4  = "return yHlTCfB[0] + yHlTCfB[2] + yHlTCfB[4] + \".F\" + yHlTCfB[7] + yHlTCfB[9] + yHlTCfB[12] + yHlTCfB[14];" fullword ascii
    $s5  = "dKwMz.open(oiNFq,jTycz,false);" fullword ascii
    $s6  = "return BCeNa;" fullword ascii
    $s7  = "function hPEz(DwStq) {" fullword ascii
    $s8  = "return EUsuByg" fullword ascii
    $s9  = "function NXDg(UhZmU) {" fullword ascii
    $s10 = "function RLdZkKm(KKTt) {" fullword ascii
    $s11 = "return DkEb.responseBody;" fullword ascii
    $s12 = "if (((new Date())>0,7417679888)) {" fullword ascii
    $s13 = "function EeKs(cfCRE) {" fullword ascii
    $s14 = "function qWIU(cyNHX) {" fullword ascii
    $s15 = "function ruZm(efPMs,ZIJPH) {" fullword ascii
    $s16 = "function tNExn(ZFgWmf) {" fullword ascii
    $s17 = "return Kk.ExpandEnvironmentStrings(mfLSw[6]);" fullword ascii
    $s18 = "function VyFA(flftv,Lozrp) {" fullword ascii
    $s19 = "function JoiK(pYfzA) {" fullword ascii
    $s20 = "function xBMnbPYAz(VIQlJYpxPiS) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}