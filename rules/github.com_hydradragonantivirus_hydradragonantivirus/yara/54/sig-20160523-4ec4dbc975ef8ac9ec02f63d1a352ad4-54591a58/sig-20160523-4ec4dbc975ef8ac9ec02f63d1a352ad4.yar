rule sig_20160523_4ec4dbc975ef8ac9ec02f63d1a352ad4 {
  meta:
    description = "datamaliciousorder - file 20160523_4ec4dbc975ef8ac9ec02f63d1a352ad4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "912690b70ec9d2e7a89013140b577da55cdc236f2b193fe2d1849d35670e91aa"

  strings:
    $s1  = "function rLkOhAXa(BHHNG) {var thaZtOlM=pozcZuwzSDIsiIgr[13];for(var VvsyI=0;VvsyI<BHHNG;VvsyI++){uVoTC+=thaZtOlM.charAt(Math.flo" ascii
    $s2  = "function JUHeEAruME(sniJvapW,MAgUcefJCEkT) {sniJvapW.Run(MAgUcefJCEkT, 0x1, 0x0);}" fullword ascii
    $s3  = "function rLkOhAXa(BHHNG) {var thaZtOlM=pozcZuwzSDIsiIgr[13];for(var VvsyI=0;VvsyI<BHHNG;VvsyI++){uVoTC+=thaZtOlM.charAt(Math.flo" ascii
    $s4  = "function ZMyzfJ(TSFzFc){return TSFzFc.ExpandEnvironmentStrings(pozcZuwzSDIsiIgr[9])}" fullword ascii
    $s5  = "function HjLgX(TSFzFc){return new ActiveXObject(TSFzFc);}" fullword ascii
    $s6  = "function AlSCteT(nFFdz) {nFFdz.close();}" fullword ascii
    $s7  = "or(Math.random()*thaZtOlM.length));}return uVoTC;}" fullword ascii
    $s8  = "IE, false);VGnTWhP.send();}" fullword ascii
    $s9  = "<khQPqO.length;IVOhfRBn++) {HMzBkgP+=SlFWR[khQPqO[IVOhfRBn]];}return HMzBkgP.substring(3,HMzBkgP.length);}" fullword ascii
    $s10 = "function wghy(VVfUIE,VGnTWhP){ZbvT = pozcZuwzSDIsiIgr[10].split(pozcZuwzSDIsiIgr[11]);VGnTWhP.open(ZbvT[0]+ZbvT[2]+ZbvT[3], VVfU" ascii
    $s11 = "function ogSRF(QtkbsrFH,ZGacv,CTrRYjfalu){Cfse(QtkbsrFH);aAmxSFED(QtkbsrFH);bgLdlSS(QtkbsrFH,ZGacv);iMrMVqaIq(QtkbsrFH);GpUb(Qtk" ascii
    $s12 = "if(GWVk>Irezt.length) break;" fullword ascii
    $s13 = "function WTnVD(rSOJdMQN,khQPqO,ilzTJaqgM){SlFWR=rSOJdMQN.split(ilzTJaqgM);HMzBkgP = pozcZuwzSDIsiIgr[12];for(IVOhfRBn=0;IVOhfRBn" ascii
    $s14 = "function wghy(VVfUIE,VGnTWhP){ZbvT = pozcZuwzSDIsiIgr[10].split(pozcZuwzSDIsiIgr[11]);VGnTWhP.open(ZbvT[0]+ZbvT[2]+ZbvT[3], VVfU" ascii
    $s15 = "function aAmxSFED(iDYiUadFC) {iDYiUadFC.type=1;}" fullword ascii
    $s16 = "function Cfse(jQikIZ) {jQikIZ.open();}" fullword ascii
    $s17 = "function GpUb(DCXjfFB,GWQcwob) {DCXjfFB.saveToFile(GWQcwob, 2);}" fullword ascii
    $s18 = "function iMrMVqaIq(JVNWBu) {var BTdpULbZtE=[];JVNWBu.position=BTdpULbZtE.length*(8377265-222);}" fullword ascii
    $s19 = "function ogSRF(QtkbsrFH,ZGacv,CTrRYjfalu){Cfse(QtkbsrFH);aAmxSFED(QtkbsrFH);bgLdlSS(QtkbsrFH,ZGacv);iMrMVqaIq(QtkbsrFH);GpUb(Qtk" ascii
    $s20 = "function LPoyrgQ() {var QgJR=100000;var MDCDeG = 100;return kxDdBfd()*(QgJR-MDCDeG)+MDCDeG;}" fullword ascii

  condition:
    uint16(0) == 0x2027 and
    8 of them
}