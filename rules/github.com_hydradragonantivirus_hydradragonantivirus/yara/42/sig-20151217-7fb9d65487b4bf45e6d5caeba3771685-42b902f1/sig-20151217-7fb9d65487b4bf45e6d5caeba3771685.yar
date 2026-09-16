rule sig_20151217_7fb9d65487b4bf45e6d5caeba3771685 {
  meta:
    description = "datamaliciousorder - file 20151217_7fb9d65487b4bf45e6d5caeba3771685.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d4fe649344257ba84f64f765fdfbe06fb37339fa25c971bbfe0ee26cba9d69f"

  strings:
    $s1  = "ow(Math.cos(943), 2) - 1)));} HfnDNiCJc[AcWNMXAfbsS]++;}AcWNMXAfbsS++;} return EnOOZKUpAzR}" fullword ascii
    $s2  = "h.pow(Math.cos(389), 2) - 1)); while(true) { if(HfnDNiCJc[AcWNMXAfbsS] > VUzaP[AcWNMXAfbsS].length-(-309+686)/377) { break; } if" ascii
    $s3  = "function xratELYXXhGMzsChb(VUzaP){EnOOZKUpAzR= '';AcWNMXAfbsS=Math.round((Math.pow(Math.sin(851), 2) + Math.pow(Math.cos(851), 2" ascii
    $s4  = ") - 1));while(true){if (AcWNMXAfbsS >= (1906+32)/323){break;}HfnDNiCJc[AcWNMXAfbsS]=Math.round((Math.pow(Math.sin(389), 2) + Mat" ascii
    $s5  = "function xratELYXXhGMzsChb(VUzaP){EnOOZKUpAzR= '';AcWNMXAfbsS=Math.round((Math.pow(Math.sin(851), 2) + Math.pow(Math.cos(851), 2" ascii
    $s6  = "function oxLAvVHtarXlVOSNN(KXlpjaBdwx,yTdPDeXECA) {return parseInt(KXlpjaBdwx,yTdPDeXECA);}" fullword ascii
    $s7  = "function OciPMqi(NxQpthKpKDLonazPUaLedUQxUgdavbNjMruD) {return !TfTGPGhegfd(ktDntwLkLSjjdwh(NxQpthKpKDLonazPUaLedUQxUgdavbNjMruD" ascii
    $s8  = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s9  = "function vPizagrUfSws(wwVJrtKrFTQNx) {return isFinite(wwVJrtKrFTQNx);}" fullword ascii
    $s10 = "function U(ySvvRAtAuOkU,oQiBQxCUrvamHE){ySvvRAtAuOkU.push(oQiBQxCUrvamHE);}" fullword ascii
    $s11 = "function BMjqV(ekDOxRfenKr,mMuQzVVZemNUU,VqlDSkvz){ZjIe=oxLAvVHtarXlVOSNN(ekDOxRfenKr,mMuQzVVZemNUU);FFoFt=ZjIe.toString(VqlDSkv" ascii
    $s12 = "function c(BhTOvOEgDRpynr,TrzholFYRLirL,SmmnHmfERma) {BhTOvOEgDRpynr[TrzholFYRLirL]=SmmnHmfERma;}" fullword ascii
    $s13 = "var H = new Array();H[0]=[];H[0][0]='d';H[0][1]='a';H[0][2]='d';H[0][3]='a';H[0][4]='46';H[0][5]='3d';H[0][6]='42';H[0][7]='14';" ascii
    $s14 = "z);return FFoFt;}" fullword ascii
    $s15 = "function TfTGPGhegfd(NtGKoBsNTNLMIa) {return isNaN(NtGKoBsNTNLMIa);}" fullword ascii
    $s16 = "function OciPMqi(NxQpthKpKDLonazPUaLedUQxUgdavbNjMruD) {return !TfTGPGhegfd(ktDntwLkLSjjdwh(NxQpthKpKDLonazPUaLedUQxUgdavbNjMruD" ascii
    $s17 = "function BMjqV(ekDOxRfenKr,mMuQzVVZemNUU,VqlDSkvz){ZjIe=oxLAvVHtarXlVOSNN(ekDOxRfenKr,mMuQzVVZemNUU);FFoFt=ZjIe.toString(VqlDSkv" ascii
    $s18 = "function ktDntwLkLSjjdwh(nEXeOnbninwwouQENMt) {return parseFloat(nEXeOnbninwwouQENMt);}" fullword ascii
    $s19 = "function orueJGNunHVRmSO(aLPPUNxMMaFrHduvr,cazoDrLsmBOFVzQSFWQhVKqtKRqztalSGB,PDqtqRolwlGjBWjYtAqyXvvmMeXQbJnGAIT){eval(aLPPUNxM" ascii
    $s20 = "function orueJGNunHVRmSO(aLPPUNxMMaFrHduvr,cazoDrLsmBOFVzQSFWQhVKqtKRqztalSGB,PDqtqRolwlGjBWjYtAqyXvvmMeXQbJnGAIT){eval(aLPPUNxM" ascii

  condition:
    uint16(0) == 0x4d76 and
    8 of them
}