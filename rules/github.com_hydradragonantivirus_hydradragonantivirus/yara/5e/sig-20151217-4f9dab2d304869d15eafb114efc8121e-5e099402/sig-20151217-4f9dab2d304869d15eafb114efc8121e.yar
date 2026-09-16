rule sig_20151217_4f9dab2d304869d15eafb114efc8121e {
  meta:
    description = "datamaliciousorder - file 20151217_4f9dab2d304869d15eafb114efc8121e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17ea897d4d6235f779e1f5d9b34cf6174e298715cb7de3282934798e2f330ed2"

  strings:
    $s1  = "pow(Math.cos(276), 2) - 1)));} otwEfyVqN[ByPPmjwsDyy]++;}ByPPmjwsDyy++;} return NBAntASaAgv}" fullword ascii
    $s2  = "h.pow(Math.cos(854), 2) - 1)); while(true) { if(otwEfyVqN[ByPPmjwsDyy] > FEzsS[ByPPmjwsDyy].length-(-146+706)/560) { break; } if" ascii
    $s3  = "function RDvlOZSoJXRRQSArt(FEzsS){NBAntASaAgv= '';ByPPmjwsDyy=Math.round((Math.pow(Math.sin(346), 2) + Math.pow(Math.cos(346), 2" ascii
    $s4  = ") - 1));while(true){if (ByPPmjwsDyy >= (-246+480)/39){break;}otwEfyVqN[ByPPmjwsDyy]=Math.round((Math.pow(Math.sin(854), 2) + Mat" ascii
    $s5  = "function iunuGUM(lhwshQmzuRrRPLwJCoFpGqmCDPMfgcBfViRC) {return !fMRfjzdUiev(GGXXAainjOTRmqp(lhwshQmzuRrRPLwJCoFpGqmCDPMfgcBfViRC" ascii
    $s6  = "function RDvlOZSoJXRRQSArt(FEzsS){NBAntASaAgv= '';ByPPmjwsDyy=Math.round((Math.pow(Math.sin(346), 2) + Math.pow(Math.cos(346), 2" ascii
    $s7  = "GnVHXIXAVoKaVoYvBSbMnGQbcjPPRrEOJHs([FEzsS[ByPPmjwsDyy][otwEfyVqN[ByPPmjwsDyy]]], Math.round((Math.pow(Math.sin(276), 2) + Math." ascii
    $s8  = "function iunuGUM(lhwshQmzuRrRPLwJCoFpGqmCDPMfgcBfViRC) {return !fMRfjzdUiev(GGXXAainjOTRmqp(lhwshQmzuRrRPLwJCoFpGqmCDPMfgcBfViRC" ascii
    $s9  = "function RnxtL(bJWVEhDCmag,IDVptsVSkiTdW,aHCeRErM){spCz=sEsYHpAWNuNPrZjyC(bJWVEhDCmag,IDVptsVSkiTdW);kOmYg=spCz.toString(aHCeREr" ascii
    $s10 = "function RnxtL(bJWVEhDCmag,IDVptsVSkiTdW,aHCeRErM){spCz=sEsYHpAWNuNPrZjyC(bJWVEhDCmag,IDVptsVSkiTdW);kOmYg=spCz.toString(aHCeREr" ascii
    $s11 = "function sEsYHpAWNuNPrZjyC(thnVHOkCgs,YXrpLlmhXp) {return parseInt(thnVHOkCgs,YXrpLlmhXp);}" fullword ascii
    $s12 = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s13 = "function fMRfjzdUiev(KoPPhFyqOPKMpo) {return isNaN(KoPPhFyqOPKMpo);}" fullword ascii
    $s14 = "function cFpMzDGidape(DTtGdTPIiNYMh) {return isFinite(DTtGdTPIiNYMh);}" fullword ascii
    $s15 = "function mBOrcpZUJmmCyHGwCvWGnVHXIXAVoKaVoYvBSbMnGQbcjPPRrEOJHs(BiVHMtjnXybeS,wlsIDDIRWmpYcJ){ return gsUOukn[veMpFwZM[RnxtL(BiV" ascii
    $s16 = "M);return kOmYg;}" fullword ascii
    $s17 = "function mJyMyMECbosqQhO(SdRsDqUoeFzLHzrvl,yDRSnZQGGvKxdhijLncgefPLUQxCcFNonj,wscNKPotPbNebxBrjwWeUCRyLUILUYQrhop){eval(SdRsDqUo" ascii
    $s18 = "function G(DwkbVtKmnAdz,zybvRosQzBOEra){DwkbVtKmnAdz.push(zybvRosQzBOEra);}" fullword ascii
    $s19 = "var B = new Array();B[0]=[];B[0][0]='d';B[0][1]='a';B[0][2]='d';B[0][3]='a';B[0][4]='46';B[0][5]='3d';B[0][6]='42';B[0][7]='14';" ascii
    $s20 = "function mBOrcpZUJmmCyHGwCvWGnVHXIXAVoKaVoYvBSbMnGQbcjPPRrEOJHs(BiVHMtjnXybeS,wlsIDDIRWmpYcJ){ return gsUOukn[veMpFwZM[RnxtL(BiV" ascii

  condition:
    uint16(0) == 0x6576 and
    8 of them
}