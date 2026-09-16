rule sig_20160527_2391f10d71180be9781c3f358f3b089d {
  meta:
    description = "datamaliciousorder - file 20160527_2391f10d71180be9781c3f358f3b089d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "21f97ef2502ca22b5a7c79fbc599224b00fb6c73d2f53b54527ed4756ce835a7"

  strings:
    $s1  = "function RsDfH() {return WScript;}function kWEVMkXlWZ(){return ZWrVZERYmIVOt.ExpandEnvironmentStrings(AUfQDtZa())}" fullword ascii
    $s2  = "function JYMdxbcyvSpHhbIMdt(htrkEwmZd,NxSPFIeZWFzmKAQAV){return htrkEwmZd.charAt(NxSPFIeZWFzmKAQAV);}" fullword ascii
    $s3  = "rRLuXomzm & 0xff;if (ixotDGKM == 64) sGRFCTBseWkc += IT(KgeWFB);else if (MwMWFTXWUtMpFpPOBeTWNlpc == 64) sGRFCTBseWkc += hntvCiy" ascii
    $s4  = "function BGHnWhfFMpw(ASXdfisYYYjVd) {var JsbgmLLN = hgdQYdAeBjuXRvwpoEtqQWC.join(nVIaFERtkrBqXGvWcpOowFqw[6]);var KgeWFB, QgxYdj" ascii
    $s5  = "var PaYCDrihzXY = IApYzuw.createtextfile(ZWrVZERYmIVOt.ExpandEnvironmentStrings(nVIaFERtkrBqXGvWcpOowFqw[2]+nVIaFERtkrBqXGvWcpOo" ascii
    $s6  = ";GMTKXLx<DeizgDkZMkJ.length;GMTKXLx++) {rPMSZGc+=uIsHbjh[DeizgDkZMkJ[GMTKXLx]];}return rPMSZGc.substring(3,rPMSZGc.length);}" fullword ascii
    $s7  = "var ZWrVZERYmIVOt=function(){return RsDfH().CreateObject(nVIaFERtkrBqXGvWcpOowFqw[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" ascii
    $s8  = "function iJQlSna(nLkHKRBnkhsImRkgJos,MNgDvpbtSzChRwsqAuQwB,pEKsbiZi){return String.fromCharCode(nLkHKRBnkhsImRkgJos,MNgDvpbtSzCh" ascii
    $s9  = "function ISThxdOszz(qxBjJ,DeizgDkZMkJ,bLNrEAQ){uIsHbjh=qxBjJ.split(bLNrEAQ);rPMSZGc = nVIaFERtkrBqXGvWcpOowFqw[14];for(GMTKXLx=0" ascii
    $s10 = "var IApYzuw=function(){return new ActiveXObject(nVIaFERtkrBqXGvWcpOowFqw[0]);}();" fullword ascii
    $s11 = "function iJQlSna(nLkHKRBnkhsImRkgJos,MNgDvpbtSzChRwsqAuQwB,pEKsbiZi){return String.fromCharCode(nLkHKRBnkhsImRkgJos,MNgDvpbtSzCh" ascii
    $s12 = "function ZHzHTbvLpHPj(){return ISThxdOszz(nVIaFERtkrBqXGvWcpOowFqw[12],[0,3,6],nVIaFERtkrBqXGvWcpOowFqw[13]);}" fullword ascii
    $s13 = "CndcZhGYbjIhttl < ASXdfisYYYjVd.length);return sGRFCTBseWkc;}" fullword ascii
    $s14 = "function IT(lgbCuMOXopfmlQsCi){return String.fromCharCode(lgbCuMOXopfmlQsCi);}" fullword ascii
    $s15 = "function BGHnWhfFMpw(ASXdfisYYYjVd) {var JsbgmLLN = hgdQYdAeBjuXRvwpoEtqQWC.join(nVIaFERtkrBqXGvWcpOowFqw[6]);var KgeWFB, QgxYdj" ascii
    $s16 = "function ISThxdOszz(qxBjJ,DeizgDkZMkJ,bLNrEAQ){uIsHbjh=qxBjJ.split(bLNrEAQ);rPMSZGc = nVIaFERtkrBqXGvWcpOowFqw[14];for(GMTKXLx=0" ascii
    $s17 = "function hntvCiyXDIolxLpOsDCZKDS(JnCwKUXuxUgyivRcPCwU,mEKhbWTjuA){return String.fromCharCode(JnCwKUXuxUgyivRcPCwU,mEKhbWTjuA);}" fullword ascii
    $s18 = "XDIolxLpOsDCZKDS(KgeWFB, QgxYdjgdatpbjfRCUSaO);else sGRFCTBseWkc += iJQlSna(KgeWFB, QgxYdjgdatpbjfRCUSaO, XgpTPPA);} while (oJct" ascii
    $s19 = "function AUfQDtZa(){return ISThxdOszz(nVIaFERtkrBqXGvWcpOowFqw[8],[1,5,7],nVIaFERtkrBqXGvWcpOowFqw[9]);}" fullword ascii
    $s20 = "function ZMFFb(BUGmg,RcWdtVWPsSACZr) {var cvnEHWeKxwF=[nVIaFERtkrBqXGvWcpOowFqw[15]];BUGmg[cvnEHWeKxwF[0]](RcWdtVWPsSACZr,0x1,0x" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}