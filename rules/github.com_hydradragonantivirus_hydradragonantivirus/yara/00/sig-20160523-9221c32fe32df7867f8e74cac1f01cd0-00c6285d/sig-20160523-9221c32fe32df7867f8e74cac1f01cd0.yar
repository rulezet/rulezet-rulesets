rule sig_20160523_9221c32fe32df7867f8e74cac1f01cd0 {
  meta:
    description = "datamaliciousorder - file 20160523_9221c32fe32df7867f8e74cac1f01cd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "973bde68754e99b2391353596d4cfb5a40e4f2266876d8716521623f1878b3df"

  strings:
    $s1  = "function NFQRBOehZs(oRDvvmDI,iBBRMHBFcooJ) {oRDvvmDI.Run(iBBRMHBFcooJ, 0x1, 0x0);}" fullword ascii
    $s2  = "function OKaYSBcvgy() {return/*TBbeJeyHtbcZOsbybBOgixkWCIiqtBfRUqWjsMytEbyxhYAqUcOfSgaTvRHUFczkDySQOgAytuBThyeEmbHFvMnBVPHuHDLtG" ascii
    $s3  = "function gPOEtxYN(saYaL) {var cgUtFtZu=VxUXXCfQZfJi[13];for(var OjKbw=0;OjKbw<saYaL;OjKbw++){pMsSY+=cgUtFtZu.charAt(Math.floor(M" ascii
    $s4  = "function gPOEtxYN(saYaL) {var cgUtFtZu=VxUXXCfQZfJi[13];for(var OjKbw=0;OjKbw<saYaL;OjKbw++){pMsSY+=cgUtFtZu.charAt(Math.floor(M" ascii
    $s5  = "ath.random()*cgUtFtZu.length));}return pMsSY;}" fullword ascii
    $s6  = "Fhp.length;OvxLInFK++) {eugFSsH+=hUpHH[zdJFhp[OvxLInFK]];}return eugFSsH.substring(3,eugFSsH.length);}" fullword ascii
    $s7  = "function RYCDAHm() {var YOso=100000;var ZIdshd = 100;return SvLZIPx()*(YOso-ZIdshd)+ZIdshd;}" fullword ascii
    $s8  = "function MUAi(KaOLTI,wMmRXkt){eAwn = VxUXXCfQZfJi[10].split(VxUXXCfQZfJi[11]);wMmRXkt.open(eAwn[0]+eAwn[2]+eAwn[3], KaOLTI, fals" ascii
    $s9  = "function OKaYSBcvgy() {return/*TBbeJeyHtbcZOsbybBOgixkWCIiqtBfRUqWjsMytEbyxhYAqUcOfSgaTvRHUFczkDySQOgAytuBThyeEmbHFvMnBVPHuHDLtG" ascii
    $s10 = "function SvLZIPx(){return Math.random();}" fullword ascii
    $s11 = "function GGsqFWMr(YHEgrjJjg) {YHEgrjJjg.type=1;}" fullword ascii
    $s12 = "function ZTVsgH(zHoTnP){return zHoTnP.ExpandEnvironmentStrings(VxUXXCfQZfJi[9])}" fullword ascii
    $s13 = "function VWMCE(ffxdyfLX,zdJFhp,nJcTRpqiN){hUpHH=ffxdyfLX.split(nJcTRpqiN);eugFSsH = VxUXXCfQZfJi[12];for(OvxLInFK=0;OvxLInFK<zdJ" ascii
    $s14 = "if(BDxq>gXpsE.length) break;" fullword ascii
    $s15 = "function WZXdo(LtBSHrxb,hWash,TickPWZlzE){boGF(LtBSHrxb);GGsqFWMr(LtBSHrxb);WlNAcnm(LtBSHrxb,hWash);pxgnvcRRP(LtBSHrxb);PUys(LtB" ascii
    $s16 = "function boGF(ehvlIT) {ehvlIT.open();}" fullword ascii
    $s17 = "function ZTBcnPByzByKb() {OKaYSBcvgy().Sleep(2295350-586);}" fullword ascii
    $s18 = "function WlNAcnm(vjYR,szlAh) {vjYR.write(szlAh);}" fullword ascii
    $s19 = "function teYbg(zHoTnP){return new ActiveXObject(zHoTnP);}" fullword ascii
    $s20 = "function PUys(EScesgG,HobnumD) {EScesgG.saveToFile(HobnumD, 2);}" fullword ascii

  condition:
    uint16(0) == 0x1227 and
    8 of them
}