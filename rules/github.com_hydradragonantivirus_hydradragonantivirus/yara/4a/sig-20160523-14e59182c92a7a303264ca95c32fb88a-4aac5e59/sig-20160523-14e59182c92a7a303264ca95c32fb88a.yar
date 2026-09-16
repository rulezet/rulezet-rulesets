rule sig_20160523_14e59182c92a7a303264ca95c32fb88a {
  meta:
    description = "datamaliciousorder - file 20160523_14e59182c92a7a303264ca95c32fb88a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b43ff6ecab966c67f065b12ecff03ae1f4f09b2d3fb1f6f959e5021e0d353cfc"

  strings:
    $s1  = "function AnZjVVzkTE() {return/*EXVIolGpmgOlAHTYPfYeeluqemPunEVnaRmwNfDBGSZvarEYtkDhohRqBEIkowOQBexIHxwpMphKBOqTfjHADaRxburdHQyGt" ascii
    $s2  = "function eMXJZeZFDm(QaZaJZki,bmBeUGVYqEQz) {QaZaJZki.Run(bmBeUGVYqEQz, 0x1, 0x0);}" fullword ascii
    $s3  = "function amSrKAQG(DJVKc) {var XKHUADft=ffYJGgV[13];for(var pSQxE=0;pSQxE<DJVKc;pSQxE++){dltjy+=XKHUADft.charAt(Math.floor(Math.r" ascii
    $s4  = "function amSrKAQG(DJVKc) {var XKHUADft=ffYJGgV[13];for(var pSQxE=0;pSQxE<DJVKc;pSQxE++){dltjy+=XKHUADft.charAt(Math.floor(Math.r" ascii
    $s5  = "function PwIICKgWtzzgx() {AnZjVVzkTE().Sleep(2330852-330);}" fullword ascii
    $s6  = "function SFJoZIF() {var nfOI=100000;var mIJSTj = 100;return VYfjFGv()*(nfOI-mIJSTj)+mIJSTj;}" fullword ascii
    $s7  = "function HoMX(RpRUfMQ,DiiDwel) {RpRUfMQ.saveToFile(DiiDwel, 2);}" fullword ascii
    $s8  = "function RdmgNV(IVyJBM){return IVyJBM.ExpandEnvironmentStrings(ffYJGgV[9])}" fullword ascii
    $s9  = "function RxGH(LClbEs) {LClbEs.open();}" fullword ascii
    $s10 = "ength;qryJgldv++) {LptcDim+=KgDhh[JuJIcR[qryJgldv]];}return LptcDim.substring(3,LptcDim.length);}" fullword ascii
    $s11 = "function lgtUxctV(DITrNogjW) {DITrNogjW.type=1;}" fullword ascii
    $s12 = "function WSia(RPkBzH,VYEREga){wGsH = ffYJGgV[10].split(ffYJGgV[11]);VYEREga.open(wGsH[0]+wGsH[2]+wGsH[3], RPkBzH, false);VYEREga" ascii
    $s13 = "function KlZGO(gunkurGO,aHXfC,NEUyVuXvRj){RxGH(gunkurGO);lgtUxctV(gunkurGO);sFCoIht(gunkurGO,aHXfC);ALRIWMAYR(gunkurGO);HoMX(gun" ascii
    $s14 = "andom()*XKHUADft.length));}return dltjy;}" fullword ascii
    $s15 = "function DUDRQpT(Hqgwh) {Hqgwh.close();}" fullword ascii
    $s16 = "function sFCoIht(MIxW,PvqPM) {MIxW.write(PvqPM);}" fullword ascii
    $s17 = "if(Hvih>sDtJM.length) break;" fullword ascii
    $s18 = "function VYfjFGv(){return Math.random();}" fullword ascii
    $s19 = "function AnZjVVzkTE() {return/*EXVIolGpmgOlAHTYPfYeeluqemPunEVnaRmwNfDBGSZvarEYtkDhohRqBEIkowOQBexIHxwpMphKBOqTfjHADaRxburdHQyGt" ascii
    $s20 = "function IqyDi(rCCOKceG,JuJIcR,oxtSFAnkV){KgDhh=rCCOKceG.split(oxtSFAnkV);LptcDim = ffYJGgV[12];for(qryJgldv=0;qryJgldv<JuJIcR.l" ascii

  condition:
    uint16(0) == 0x1127 and
    8 of them
}