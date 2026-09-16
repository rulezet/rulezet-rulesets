rule sig_20151217_2a1f19cf822dd4d20b58e2c0bb6dacb5 {
  meta:
    description = "datamaliciousorder - file 20151217_2a1f19cf822dd4d20b58e2c0bb6dacb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5aca3e9585f0a6893f13d3fb44c4fa115a6bc42cd0c82077ff58aa43f204977a"

  strings:
    $s1  = "function nytMPEzYAagGHjtNu(YTLjF){WXMlxJbTKMl= '';DfLgRwyrvdm=Math.round((Math.pow(Math.sin(290), 2) + Math.pow(Math.cos(290), 2" ascii
    $s2  = "w(Math.cos(62), 2) - 1)));} bbPgFDklh[DfLgRwyrvdm]++;}DfLgRwyrvdm++;} return WXMlxJbTKMl}" fullword ascii
    $s3  = ") - 1));while(true){if (DfLgRwyrvdm >= (4027+209)/706){break;}bbPgFDklh[DfLgRwyrvdm]=Math.round((Math.pow(Math.sin(716), 2) + Ma" ascii
    $s4  = "th.pow(Math.cos(716), 2) - 1)); while(true) { if(bbPgFDklh[DfLgRwyrvdm] > YTLjF[DfLgRwyrvdm].length-(61+121)/182) { break; } if " ascii
    $s5  = "function nytMPEzYAagGHjtNu(YTLjF){WXMlxJbTKMl= '';DfLgRwyrvdm=Math.round((Math.pow(Math.sin(290), 2) + Math.pow(Math.cos(290), 2" ascii
    $s6  = "function SFBwrOF(ZXUiXPGxFxacQDrrXceuLqekSueuBbgZOqmb) {return !mTEiLXyGyPh(FuZFUdmolpyRuNu(ZXUiXPGxFxacQDrrXceuLqekSueuBbgZOqmb" ascii
    $s7  = "function SFBwrOF(ZXUiXPGxFxacQDrrXceuLqekSueuBbgZOqmb) {return !mTEiLXyGyPh(FuZFUdmolpyRuNu(ZXUiXPGxFxacQDrrXceuLqekSueuBbgZOqmb" ascii
    $s8  = "function FuZFUdmolpyRuNu(JyZejzktKcTnrGUquXJ) {return parseFloat(JyZejzktKcTnrGUquXJ);}" fullword ascii
    $s9  = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s10 = "function d(WPsndIOSSJxb,UPsojCTwsIOafz){WPsndIOSSJxb.push(UPsojCTwsIOafz);}" fullword ascii
    $s11 = "function cmpKPVGxnjWEjaifbEEtrVjopUuBTGvtvlTVWABRSggLCRJtQbGaLu(ntPsMCsqXHdBP,rrtdGMBfzlwKsg){ return eKWVHOY[JrrRNyOG[oOKsj(ntP" ascii
    $s12 = "function cmpKPVGxnjWEjaifbEEtrVjopUuBTGvtvlTVWABRSggLCRJtQbGaLu(ntPsMCsqXHdBP,rrtdGMBfzlwKsg){ return eKWVHOY[JrrRNyOG[oOKsj(ntP" ascii
    $s13 = "function JrWiSbSMSnAuiUZ(LZteCtrbspowFyuWu,jZgxstPIWTwVJdmumeGzUoJtSjWmttsPrp,jlshTJFCZpVszfZiSowSqMrMcXyNVXSJzCL){eval(LZteCtrb" ascii
    $s14 = "function mTEiLXyGyPh(DVzdIfeUFuECFM) {return isNaN(DVzdIfeUFuECFM);}" fullword ascii
    $s15 = "function oOKsj(oYzziltkffw,eSFFftUTFkfgy,xuRfjEPl){shfO=DMGsIDGUswljRKDSb(oYzziltkffw,eSFFftUTFkfgy);AoVQw=shfO.toString(xuRfjEP" ascii
    $s16 = "var R = new Array();R[0]=[];R[0][0]='d';R[0][1]='a';R[0][2]='d';R[0][3]='a';R[0][4]='46';R[0][5]='3d';R[0][6]='42';R[0][7]='14';" ascii
    $s17 = "function C(ZblclbIrjOYyfa,TdvnsIxESsQPx,stLsrtMyvFm) {ZblclbIrjOYyfa[TdvnsIxESsQPx]=stLsrtMyvFm;}" fullword ascii
    $s18 = "function OtCNQpvZQyCF(ZNQNfKxZLUvVf) {return isFinite(ZNQNfKxZLUvVf);}" fullword ascii
    $s19 = "function oOKsj(oYzziltkffw,eSFFftUTFkfgy,xuRfjEPl){shfO=DMGsIDGUswljRKDSb(oYzziltkffw,eSFFftUTFkfgy);AoVQw=shfO.toString(xuRfjEP" ascii
    $s20 = "function DMGsIDGUswljRKDSb(MwoVTLbTIR,iUxhZwVlrO) {return parseInt(MwoVTLbTIR,iUxhZwVlrO);}" fullword ascii

  condition:
    uint16(0) == 0x724a and
    8 of them
}