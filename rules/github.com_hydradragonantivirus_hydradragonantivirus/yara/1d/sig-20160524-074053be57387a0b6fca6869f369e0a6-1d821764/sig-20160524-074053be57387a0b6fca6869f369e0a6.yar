rule sig_20160524_074053be57387a0b6fca6869f369e0a6 {
  meta:
    description = "datamaliciousorder - file 20160524_074053be57387a0b6fca6869f369e0a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e76836235eaada7fee68ad5096a20f394c9b250f50c841b570be29ae6a3fcb7"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "KGaxLGFhHUPsKpCHGhqhHpevwfrEmublOBFvordOwiSvzSYThMSpGKzmIcsQxHuGMQeNLvuPfOPRhOozCLoQAyNxOslxCnGwDyw*/WScript;}function sgkppLhxQ" ascii
    $s3  = "ljWwHlr, 2);}function paJBosO(qpqle) {qpqle.close();}function TYnHWUEsXl(wcVAAeoT,bpaULbEIPgZP) {wcVAAeoT.Run(bpaULbEIPgZP, 0x1," ascii
    $s4  = "NF[dnOZ];var LjoEPDA=iCCYZZp() + iKNbMZYEEJWXNs[2];var XpoqCRba=958-957;var TBbwTVbXc = function(){return new ActiveXObject(Qipb" ascii
    $s5  = "zBUxNlGDqfO[3])+String.fromCharCode(92)+uSrVXTQpr;fbqMUfKMTtGMUP = TVTlV.OpenTextFile(KPUzxqqv,2,true);fbqMUfKMTtGMUP.Write('var" ascii
    $s6  = ";yfaQesvr<CLnlkm.length;yfaQesvr++) {ExKgnbL+=JZqSk[CLnlkm[yfaQesvr]];}return ExKgnbL.substring(3,ExKgnbL.length);}function ybTF" ascii
    $s7  = "x74\",\"\\x4b\\x6b\\x71\\x53\\x53\\x4a\\x49\\x66\\x41\\x54\\x58\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];functi" ascii
    $s8  = "status == 100+100) {var fDURDPT = function() {return new ActiveXObject(QipbP(iKNbMZYEEJWXNs[7],[0,2,4],iKNbMZYEEJWXNs[8]));}();x" ascii
    $s9  = "m = function(){return new ActiveXObject(QipbP(iKNbMZYEEJWXNs[5],[0,2,4],iKNbMZYEEJWXNs[6]));}();uYuF(QccDmaVMA,XHhKm);if (XHhKm." ascii
    $s10 = ".open();wZoRqNhM(aHUUKAHn);TrSDzqA(aHUUKAHn,IhfrE);sgkppLhxQ(aHUUKAHn);Uthk(aHUUKAHn,RKmLyvDOtM);paJBosO(aHUUKAHn);}function uYu" ascii
    $s11 = " 0x0);}function iCCYZZp() {var bKFK=100000;var fMzacf = 100;return nDJWjBg()*(bKFK-fMzacf)+fMzacf;}function kVkmTHug(dWamV) {var" ascii
    $s12 = ");var dlINF = [iKNbMZYEEJWXNs[0], iKNbMZYEEJWXNs[1]];var dnOZ=804-804;while(true) {if(dnOZ>dlINF.length) break;var QccDmaVMA=dlI" ascii
    $s13 = ";function (fWmEugBOCdxE) {return new ActiveXObject(fWmEugBOCdxE);}" fullword ascii
    $s14 = "F(qaTAwh,IvrdeOg){ZaEt = iKNbMZYEEJWXNs[10].split(iKNbMZYEEJWXNs[11]);IvrdeOg.open(ZaEt[0]+ZaEt[2]+ZaEt[3], qaTAwh, false);Ivrde" ascii
    $s15 = "Og.send();}function QipbP(tlmXPGbO,CLnlkm,nMTuTrhVx){JZqSk=tlmXPGbO.split(nMTuTrhVx);ExKgnbL = iKNbMZYEEJWXNs[12];for(yfaQesvr=0" ascii
    $s16 = "KMTtGMUP;var TVTlV=function(){return new ActiveXObject(zBUxNlGDqfO[0]);}();var ltjTGFYzJIstLr=function(){return new ActiveXObjec" ascii
    $s17 = "(oNyzAu) {var RwGUAkrFXW=[];oNyzAu.position=RwGUAkrFXW.length*(2452268-375);}function Uthk(YBDfRWi,ljWwHlr) {YBDfRWi.saveToFile(" ascii
    $s18 = "tion qYIbhR(NjHzIu){return NjHzIu.ExpandEnvironmentStrings(iKNbMZYEEJWXNs[9])}function xtISI(aHUUKAHn,IhfrE,RKmLyvDOtM){aHUUKAHn" ascii
    $s19 = "jIOGHJdxy() {ZWIsAoDYdC().Sleep(3559-671);}function nDJWjBg(){return Math.random();}function jPNa(NYmWub) {NYmWub.open();}functi" ascii
    $s20 = "h));}return MKVIY;}function UoKbQySEtYKDDt(YqSPUIkQiZdBag) {return new ActiveXObject(YqSPUIkQiZdBag);}');var BUQsVBnn=[\"\\x77" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}