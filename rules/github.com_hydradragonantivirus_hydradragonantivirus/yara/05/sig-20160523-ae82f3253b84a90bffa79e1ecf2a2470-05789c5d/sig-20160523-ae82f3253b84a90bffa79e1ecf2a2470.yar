rule sig_20160523_ae82f3253b84a90bffa79e1ecf2a2470 {
  meta:
    description = "datamaliciousorder - file 20160523_ae82f3253b84a90bffa79e1ecf2a2470.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d896fbb702b494c81c43589fc5e543bdae0b6207e0a3d49c732431f8b9038c9"

  strings:
    $s1  = "function lWFRyxJabu(dMQtAtqz,kMBqUkTYNErc) {dMQtAtqz.Run(kMBqUkTYNErc, 0x1, 0x0);}" fullword ascii
    $s2  = "function BpdqjyJV(xZnbv) {var eGHIyhmp=nuolvklaBawcFhAsavwxczc[2];for(var tINUA=0;tINUA<xZnbv;tINUA++){AJDeB+=eGHIyhmp.charAt(Ma" ascii
    $s3  = "function BpdqjyJV(xZnbv) {var eGHIyhmp=nuolvklaBawcFhAsavwxczc[2];for(var tINUA=0;tINUA<xZnbv;tINUA++){AJDeB+=eGHIyhmp.charAt(Ma" ascii
    $s4  = "function gZZZewmFq(ZprHTdkCV,IosdIox,QjuIhPuq){" fullword ascii
    $s5  = "function RPFBR(gDorNRjP,NFdjMG,oZOeJizLF){gbqwy=gDorNRjP.split(oZOeJizLF);rQTCNEc = nuolvklaBawcFhAsavwxczc[13];for(jXMTaOTT=0;j" ascii
    $s6  = "function oqXXzoJW(jgwvpxULq) {jgwvpxULq.type=1;}" fullword ascii
    $s7  = "XMTaOTT<NFdjMG.length;jXMTaOTT++) {rQTCNEc+=gbqwy[NFdjMG[jXMTaOTT]];}return rQTCNEc.substring(3,rQTCNEc.length);}" fullword ascii
    $s8  = "function hYTh(hDdgaF) {hDdgaF.open();}" fullword ascii
    $s9  = "function yKLsI(OffXKYTx,KgIMz,VUUplEBRri){hYTh(OffXKYTx);oqXXzoJW(OffXKYTx);rrLluwL(OffXKYTx,KgIMz);XxRuFvtJT(OffXKYTx);EbPY(Off" ascii
    $s10 = "function VIJIhue(nNOHs) {nNOHs.close();}" fullword ascii
    $s11 = "function MrhG(fAYvLC,IBjkDvF){KAcC = nuolvklaBawcFhAsavwxczc[11].split(nuolvklaBawcFhAsavwxczc[12]);IBjkDvF.open(KAcC[0]+KAcC[2]" ascii
    $s12 = "function XxRuFvtJT(hhissA) {var pjopcUFSUG=[];hhissA.position=pjopcUFSUG.length*(2525951-722);}" fullword ascii
    $s13 = "function CfcMl(JDfhoh){return new ActiveXObject(JDfhoh);}" fullword ascii
    $s14 = "function rrLluwL(xKwF,ZSbKq) {xKwF.write(ZSbKq);}" fullword ascii
    $s15 = "function sObXse(JDfhoh){return JDfhoh.ExpandEnvironmentStrings(nuolvklaBawcFhAsavwxczc[10])}" fullword ascii
    $s16 = "function qlToAnn(){return Math.random();}" fullword ascii
    $s17 = "function RPFBR(gDorNRjP,NFdjMG,oZOeJizLF){gbqwy=gDorNRjP.split(oZOeJizLF);rQTCNEc = nuolvklaBawcFhAsavwxczc[13];for(jXMTaOTT=0;j" ascii
    $s18 = "function MrhG(fAYvLC,IBjkDvF){KAcC = nuolvklaBawcFhAsavwxczc[11].split(nuolvklaBawcFhAsavwxczc[12]);IBjkDvF.open(KAcC[0]+KAcC[2]" ascii
    $s19 = "function yKLsI(OffXKYTx,KgIMz,VUUplEBRri){hYTh(OffXKYTx);oqXXzoJW(OffXKYTx);rrLluwL(OffXKYTx,KgIMz);XxRuFvtJT(OffXKYTx);EbPY(Off" ascii
    $s20 = "th.floor(Math.random()*eGHIyhmp.length));}return AJDeB;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}