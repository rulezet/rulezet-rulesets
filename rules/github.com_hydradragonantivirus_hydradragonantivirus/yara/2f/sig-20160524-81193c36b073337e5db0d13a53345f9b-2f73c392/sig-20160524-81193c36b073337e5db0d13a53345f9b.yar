rule sig_20160524_81193c36b073337e5db0d13a53345f9b {
  meta:
    description = "datamaliciousorder - file 20160524_81193c36b073337e5db0d13a53345f9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "726fd3a18519abd81e429230ddd654af611992ab87c1603b5e2b4cf459bf8134"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "IZwBY[0]);}();var EezjY=function(){return new ActiveXObject(\"WScript.Shell\");}();var lOvdQqxL = nBpQSAfEPGSJwGIZwBY[1]+13557+n" ascii
    $s3  = "20\"];nitCwnifqnt.Close();EezjY.Run(xVglRjyFzKD[0]+NhgiDpj,0x1,0x0);}AlORuTR();function (PFDMqDSbl) {return new ActiveXObject(PF" ascii
    $s4  = "rTEYxbuNknOUUaTGunmGbyZiIFLVHiBgPeYAxSkozwNimpNtBuQGLlZg*/WScript;}function pHZRkPHxs(iABeiK) {var qnPPBkAVtM=[];iABeiK.position" ascii
    $s5  = "close();}function vCYesfuvGk(cOWlwnAX,AydPMAQCeXAD) {cOWlwnAX.Run(AydPMAQCeXAD, 0x1, 0x0);}function PJyxEnA() {var nSwk=100000;v" ascii
    $s6  = "C=0;NcJeC<ruxGe;NcJeC++){fhzLP+=UdUZsdJT.charAt(Math.floor(Math.random()*UdUZsdJT.length));}return fhzLP;}function fbWqZdaxudcDb" ascii
    $s7  = "true) {if(IHcN>VNqGT.length) break;var HSTlugOjr=VNqGT[IHcN];var qQDkPwx=PJyxEnA() + YPZcSwChuUOYeHljH[2];var ktGwdvRG=163-162;v" ascii
    $s8  = "function uryZidq(){return Math.random();}function zvXo(DOJJHr) {DOJJHr.open();}function zuMJfNpU(LGpEeqjSu) {LGpEeqjSu.type=1;}f" ascii
    $s9  = "HZRkPHxs(EFtcmynE);pFEn(EFtcmynE,IFwDJbWbnu);SnaVhlz(EFtcmynE);}function fsZw(pcZstb,RUHOGnY){pXiK = YPZcSwChuUOYeHljH[10].split" ascii
    $s10 = "nDeHX(aNdEMMMwz) + String.fromCharCode(92) + qQDkPwx;var KzCaa = function(){return new ActiveXObject(oGkig(YPZcSwChuUOYeHljH[5]," ascii
    $s11 = "ar tRbBvm = 100;return uryZidq()*(nSwk-tRbBvm)+tRbBvm;}function vWyouufI(ruxGe) {var UdUZsdJT=YPZcSwChuUOYeHljH[13];for(var NcJe" ascii
    $s12 = "c+=TULLm[ojUPTS[CEAwCYzc]];}return KIBUnpc.substring(3,KIBUnpc.length);}function ILUGJuFqGjMWR() {bUqLBXZqcj().Sleep(3532-836);}" ascii
    $s13 = "ar aNdEMMMwz = function(){return new ActiveXObject(oGkig(YPZcSwChuUOYeHljH[3],[0,2,4],YPZcSwChuUOYeHljH[4]));}();var qQDkPwx = P" ascii
    $s14 = "73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function AlORuTR() {var nitCwnifqnt;var stVrN=function(){return new ActiveXObject(nBpQS" ascii
    $s15 = "=qnPPBkAVtM.length*(330138-576);}function pFEn(FatDvKx,bjNcyUP) {FatDvKx.saveToFile(bjNcyUP, 2);}function SnaVhlz(JEKRl) {JEKRl." ascii
    $s16 = "v(yMgWnDtZVibuse) {return new ActiveXObject(yMgWnDtZVibuse);}');var xVglRjyFzKD=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65" ascii
    $s17 = "ngs(YPZcSwChuUOYeHljH[9])}function cYWDQ(EFtcmynE,UgVNb,IFwDJbWbnu){EFtcmynE.open();zuMJfNpU(EFtcmynE);JXpsddY(EFtcmynE,UgVNb);p" ascii
    $s18 = "unction JXpsddY(lqzA,KOJZZ) {lqzA.write(KOJZZ);}function bUqLBXZqcj() {return/*MlElpODgSQaAhKrytnCEpReXfnXjAVErMGYcBLEtddtWeZQPQ" ascii
    $s19 = "qnt = stVrN.OpenTextFile(NhgiDpj,2,true);nitCwnifqnt.Write('var YPZcSwChuUOYeHljH=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x" ascii
    $s20 = "IgUMhRqxPNkNgaQzdjRYeszejgAiQE*/ILUGJuFqGjMWR();var VNqGT = [YPZcSwChuUOYeHljH[0], YPZcSwChuUOYeHljH[1]];var IHcN=257-257;while(" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}