rule sig_20160523_34d255613445f90b9932895ae691cda0 {
  meta:
    description = "datamaliciousorder - file 20160523_34d255613445f90b9932895ae691cda0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4f84fac2027f7feb721c9525b05d6dd906e8b82d64648553e4c82b4b678d7d4"

  strings:
    $s1  = "function ToAnnhYThh(DdgaFoqX,XzoJWjgwvpxU) {DdgaFoqX.Run(XzoJWjgwvpxU, 0x1, 0x0);}" fullword ascii
    $s2  = "function xgBYfXuG(Vqfag) {var bGOwyvYe=oVZaeDewXrxFQ[2];for(var xxkNr=0;xxkNr<Vqfag;xxkNr++){lDLXI+=bGOwyvYe.charAt(Math.floor(M" ascii
    $s3  = "function xgBYfXuG(Vqfag) {var bGOwyvYe=oVZaeDewXrxFQ[2];for(var xxkNr=0;xxkNr<Vqfag;xxkNr++){lDLXI+=bGOwyvYe.charAt(Math.floor(M" ascii
    $s4  = "ath.random()*bGOwyvYe.length));}return lDLXI;}" fullword ascii
    $s5  = "hohs.length;NOwiyKLs++) {KYTxKgI+=IOffX[Dfhohs[NOwiyKLs]];}return KYTxKgI.substring(3,KYTxKgI.length);}" fullword ascii
    $s6  = "function kERPFBRgD(orNRjP) {var NFdjMGoZOe=[];orNRjP.position=NFdjMGoZOe.length*(7123066-604);}" fullword ascii
    $s7  = "function IoxQj(uIhPuq){return new ActiveXObject(uIhPuq);}" fullword ascii
    $s8  = "function kORiY(TWCfcMlJ,Dfhohs,ObXsezNwD){IOffX=TWCfcMlJ.split(ObXsezNwD);KYTxKgI = oVZaeDewXrxFQ[13];for(NOwiyKLs=0;NOwiyKLs<Df" ascii
    $s9  = "function kORiY(TWCfcMlJ,Dfhohs,ObXsezNwD){IOffX=TWCfcMlJ.split(ObXsezNwD);KYTxKgI = oVZaeDewXrxFQ[13];for(NOwiyKLs=0;NOwiyKLs<Df" ascii
    $s10 = "if (bkiGeJd==0) break;" fullword ascii
    $s11 = "function pJGGDRQ() {var Qgoh=100000;var XdnycZ = 100;return UUplEBR()*(Qgoh-XdnycZ)+XdnycZ;}" fullword ascii
    $s12 = "function JizL(FjXMTaO,TTgbqwy) {FjXMTaO.saveToFile(TTgbqwy, 2);}" fullword ascii
    $s13 = "function UUplEBR(){return Math.random();}" fullword ascii
    $s14 = "function rQTCNEc(pVqql) {pVqql.close();}" fullword ascii
    $s15 = "function yFxpQj(uIhPuq){return uIhPuq.ExpandEnvironmentStrings(oVZaeDewXrxFQ[10])}" fullword ascii
    $s16 = "function OXagr(DbPDkuMJ,KdBuv,AmXjLAcsgv){riMr(DbPDkuMJ);LCIBjkDv(DbPDkuMJ);BxXXPGH(DbPDkuMJ,KdBuv);kERPFBRgD(DbPDkuMJ);JizL(DbP" ascii
    $s17 = "function LCIBjkDv(FKAcCLSVh) {FKAcCLSVh.type=1;}" fullword ascii
    $s18 = "function DOpZTRkpK(MkyYHgUsw,dQhKLDS,BrZxAGxt){" fullword ascii
    $s19 = "try{bkiGeJd=DOpZTRkpK(OKemW[Iosd], pJGGDRQ() + oVZaeDewXrxFQ[9], 1)}catch(e){}; " fullword ascii
    $s20 = "function BxXXPGH(dOlX,fiFth) {dOlX.write(fiFth);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}