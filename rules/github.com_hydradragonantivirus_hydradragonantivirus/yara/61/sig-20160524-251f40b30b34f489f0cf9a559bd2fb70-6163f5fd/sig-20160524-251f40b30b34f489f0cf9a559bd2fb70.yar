rule sig_20160524_251f40b30b34f489f0cf9a559bd2fb70 {
  meta:
    description = "datamaliciousorder - file 20160524_251f40b30b34f489f0cf9a559bd2fb70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2c8465150ebf7b149afb081c60198bbc3d30a51ce60903a89568fd0282eb8e9"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "ion(){return new ActiveXObject(eFsIWMNV[0]);}();var oQqPSM=function(){return new ActiveXObject(\"WScript.Shell\");}();var sFUlTE" ascii
    $s3  = "fFVWa, 2);}function CSmkGNW(VKEET) {VKEET.close();}function fRroJxLRPU(TPoitSxK,qnjAqJQavujk) {TPoitSxK.Run(qnjAqJQavujk, 0x1, 0" ascii
    $s4  = "JtftkbNcthpMcKphCiTALzGCWiGzZhyaoVntFvEoqhBXodLfRGlXQQGlDfchVxdvmqOntKOuHbicUpAWzZWnnbaODWSIlGcIE*/WScript;}function hHFcJPkga(U" ascii
    $s5  = "JLogSwV<BdNLaK.length;LJLogSwV++) {KLcqQYA+=bTUWq[BdNLaK[LJLogSwV]];}return KLcqQYA.substring(3,KLcqQYA.length);}function FJZARs" ascii
    $s6  = "x0);}function koPOLpR() {var updv=100000;var CocGyz = 100;return apmJNzZ()*(updv-CocGyz)+CocGyz;}function kcTobPYA(yxzAZ) {var g" ascii
    $s7  = "\\x6b\\x4d\\x59\\x58\\x49\\x54\\x73\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function DFPEXZSzYkt() {var TNvRSP" ascii
    $s8  = ");}function IHcsb(ceubBMPY,BdNLaK,bFyKPATJQ){bTUWq=ceubBMPY.split(bFyKPATJQ);KLcqQYA = CaYVGIdMmstrwIJbChrU[12];for(LJLogSwV=0;L" ascii
    $s9  = ",0x1,0x0);}DFPEXZSzYkt();function (QOnTcHxgLwyDxm) {return new ActiveXObject(QOnTcHxgLwyDxm);}" fullword ascii
    $s10 = "ength));}return IEWmD;}function eiaTQtvbAgzMat(SNIEGopMscnphn) {return new ActiveXObject(SNIEGopMscnphn);}');var ayfxyejcIxcsuai" ascii
    $s11 = "SuUhc);TdFSZue(KYTSuUhc,FXCPU);hHFcJPkga(KYTSuUhc);fxMM(KYTSuUhc,TuDuUCrIJs);CSmkGNW(KYTSuUhc);}function ERzH(oybOSI,BEqbJvf){IM" ascii
    $s12 = " vDerZNdk(bYmgtjlSt) {bYmgtjlSt.type=1;}function TdFSZue(iaoB,iUrGi) {iaoB.write(iUrGi);}function ndHCVXbbZN() {return/*JeDKxLmA" ascii
    $s13 = "trPhaUv() {ndHCVXbbZN().Sleep(3135-500);}function apmJNzZ(){return Math.random();}function RANV(QxXWkq) {QxXWkq.open();}function" ascii
    $s14 = "GoeBF) {var QtPrESpCXZ=[];UGoeBF.position=QtPrESpCXZ.length*(5640294-342);}function fxMM(RPpEDNy,zUfFVWa) {RPpEDNy.saveToFile(zU" ascii
    $s15 = ");var JmBeDau = mjVFNB(UAgEfQMDN) + String.fromCharCode(92) + JmBeDau;var txCCY = function(){return new ActiveXObject(IHcsb(CaYV" ascii
    $s16 = "7;while(true) {if(rBgo>QTcKZ.length) break;var canalzjHo=QTcKZ[rBgo];var JmBeDau=koPOLpR() + CaYVGIdMmstrwIJbChrU[2];var ZFFyPNF" ascii
    $s17 = "tion() {return new ActiveXObject(IHcsb(CaYVGIdMmstrwIJbChrU[7],[0,2,4],CaYVGIdMmstrwIJbChrU[8]));}();OwXTn(uKdBaLM,txCCY.Respons" ascii
    $s18 = "eBody,JmBeDau);}if (ZFFyPNFx > 0){try {fRroJxLRPU(UAgEfQMDN,JmBeDau);} catch(e) {}break;};rBgo++;}function mjVFNB(RVctmc){return" ascii
    $s19 = "x=659-658;var UAgEfQMDN = function(){return new ActiveXObject(IHcsb(CaYVGIdMmstrwIJbChrU[3],[0,2,4],CaYVGIdMmstrwIJbChrU[4]));}(" ascii
    $s20 = "fl = CaYVGIdMmstrwIJbChrU[10].split(CaYVGIdMmstrwIJbChrU[11]);BEqbJvf.open(IMfl[0]+IMfl[2]+IMfl[3], oybOSI, false);BEqbJvf.send(" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}