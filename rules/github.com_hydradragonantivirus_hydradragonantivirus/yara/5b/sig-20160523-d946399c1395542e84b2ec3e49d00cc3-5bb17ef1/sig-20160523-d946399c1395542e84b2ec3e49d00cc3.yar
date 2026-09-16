rule sig_20160523_d946399c1395542e84b2ec3e49d00cc3 {
  meta:
    description = "datamaliciousorder - file 20160523_d946399c1395542e84b2ec3e49d00cc3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3cafc9821011d6ea1d849b6017431ae00816988004353f8b5bc5a1a82f89781"

  strings:
    $s1  = "function WOQsJzHYgd(HnDZTwUl,YlvmbRZaEZYY) {HnDZTwUl.Run(YlvmbRZaEZYY, 0x1, 0x0);}" fullword ascii
    $s2  = "function AzyYHBFg(WtVjr) {var GiBruCZU=ZggOfSNvEUZHmD[13];for(var mOVzp=0;mOVzp<WtVjr;mOVzp++){egehk+=GiBruCZU.charAt(Math.floor" ascii
    $s3  = "function AzyYHBFg(WtVjr) {var GiBruCZU=ZggOfSNvEUZHmD[13];for(var mOVzp=0;mOVzp<WtVjr;mOVzp++){egehk+=GiBruCZU.charAt(Math.floor" ascii
    $s4  = "Eujpa.length;MdUpprcY++) {YUDWNqv+=CyrqQ[REujpa[MdUpprcY]];}return YUDWNqv.substring(3,YUDWNqv.length);}" fullword ascii
    $s5  = "(Math.random()*GiBruCZU.length));}return egehk;}" fullword ascii
    $s6  = "function VjwYY(UcucWV){return new ActiveXObject(UcucWV);}" fullword ascii
    $s7  = "function EKLn(pYNuXj,aSazLAw){xFJK = ZggOfSNvEUZHmD[10].split(ZggOfSNvEUZHmD[11]);aSazLAw.open(xFJK[0]+xFJK[2]+xFJK[3], pYNuXj, " ascii
    $s8  = "function UmEVr(AkbcuroU,REujpa,EONlDaKrD){CyrqQ=AkbcuroU.split(EONlDaKrD);YUDWNqv = ZggOfSNvEUZHmD[12];for(MdUpprcY=0;MdUpprcY<R" ascii
    $s9  = "function wrIOL(ujkIOvcl,ddJTs,sVFmZfSRkf){doyW(ujkIOvcl);gqSzWvRL(ujkIOvcl);wnVnEkT(ujkIOvcl,ddJTs);bMCwLhMim(ujkIOvcl);OoOU(ujk" ascii
    $s10 = "false);aSazLAw.send();}" fullword ascii
    $s11 = "function QKTREFO(NbYDJ) {NbYDJ.close();}" fullword ascii
    $s12 = "function wrIOL(ujkIOvcl,ddJTs,sVFmZfSRkf){doyW(ujkIOvcl);gqSzWvRL(ujkIOvcl);wnVnEkT(ujkIOvcl,ddJTs);bMCwLhMim(ujkIOvcl);OoOU(ujk" ascii
    $s13 = "function EKLn(pYNuXj,aSazLAw){xFJK = ZggOfSNvEUZHmD[10].split(ZggOfSNvEUZHmD[11]);aSazLAw.open(xFJK[0]+xFJK[2]+xFJK[3], pYNuXj, " ascii
    $s14 = "function eIICpxk(){return Math.random();}" fullword ascii
    $s15 = "if(CsZm>MsnSM.length) break;" fullword ascii
    $s16 = "function bMCwLhMim(UdEbeK) {var DequxRJreo=[];UdEbeK.position=DequxRJreo.length*(691771-627);}" fullword ascii
    $s17 = "function wnVnEkT(EIfd,mieLe) {EIfd.write(mieLe);}" fullword ascii
    $s18 = "function OoOU(JvvFayq,VQIrPNK) {JvvFayq.saveToFile(VQIrPNK, 2);}" fullword ascii
    $s19 = "function doyW(QMeqTV) {QMeqTV.open();}" fullword ascii
    $s20 = "function iHkhqSU() {var Hjrb=100000;var yFdkrV = 100;return eIICpxk()*(Hjrb-yFdkrV)+yFdkrV;}" fullword ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}