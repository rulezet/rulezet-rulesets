rule sig_20160524_79b8335446bdd14d995a8805602698b8 {
  meta:
    description = "datamaliciousorder - file 20160524_79b8335446bdd14d995a8805602698b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceeb1c9d44e9de72cedd4685d8313fe4dc3edaa92230b8456a35a673a820f046"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "aBS.Close();gmRXYTcuwN.Run(QEBFtDJIWXOVZDQz[0]+FDshkkvuXuoh,0x1,0x0);}HfmOUGZKFo();function (EEAugyUdQ) {return new ActiveXObjec" ascii
    $s3  = "uAYQQbWrFsmXfYaVhQPVeuLjNHtvBdRTlFLmkLfMo*/WScript;}function kORCJHwSl(eufomV) {var jRJMtszeEQ=[];eufomV.position=jRJMtszeEQ.len" ascii
    $s4  = "TcuwN=function(){return new ActiveXObject(\"WScript.Shell\");}();var WvPqrUMfcGw = eYRXFj[1]+17242+eYRXFj[2];var FDshkkvuXuoh=gm" ascii
    $s5  = "tHWvB.length) break;var zCWSoASCs=tHWvB[IagM];var zDbfViB=NfkqAqE() + EjhMiZNnDOqYFbUbA[2];var rOmNuCUX=722-721;var hkJPUjMBB = " ascii
    $s6  = "ion dwXSHvMtiA(WPWkGtRx,wPjLvpRakEhM) {WPWkGtRx.Run(wPjLvpRakEhM, 0x1, 0x0);}function NfkqAqE() {var xkdJ=100000;var jKqcks = 10" ascii
    $s7  = "h;DLCsE++){WRxGj+=PdOVaSPz.charAt(Math.floor(Math.random()*PdOVaSPz.length));}return WRxGj;}function CJCJreUdAoEDtN(LvPzTofXjvie" ascii
    $s8  = ") + String.fromCharCode(92) + zDbfViB;var OCvVn = function(){return new ActiveXObject(LBCJn(EjhMiZNnDOqYFbUbA[5],[0,2,4],EjhMiZN" ascii
    $s9  = "LO);pIfJ(iQOKzWLO,vyXqJAxSPE);XdHiQyN(iQOKzWLO);}function LWxc(kHTOSE,OdjRtPg){Zupi = EjhMiZNnDOqYFbUbA[10].split(EjhMiZNnDOqYFb" ascii
    $s10 = "nDOqYFbUbA[6]));}();LWxc(zCWSoASCs,OCvVn);if (OCvVn.status == 100+100) {var dHiljBL = function() {return new ActiveXObject(LBCJn" ascii
    $s11 = "gth*(9535142-682);}function pIfJ(hJQVITc,aXxHUDh) {hJQVITc.saveToFile(aXxHUDh, 2);}function XdHiQyN(lDFZC) {lDFZC.close();}funct" ascii
    $s12 = "UbA[11]);OdjRtPg.open(Zupi[0]+Zupi[2]+Zupi[3], kHTOSE, false);OdjRtPg.send();}function LBCJn(rtXpYYEK,wVrQip,vzhKCdRnW){evhsI=rt" ascii
    $s13 = "function(){return new ActiveXObject(LBCJn(EjhMiZNnDOqYFbUbA[3],[0,2,4],EjhMiZNnDOqYFbUbA[4]));}();var zDbfViB = GWAejV(hkJPUjMBB" ascii
    $s14 = "sqpvjjxjYcRohYI*/vFfQgoBIRMOhb();var tHWvB = [EjhMiZNnDOqYFbUbA[0], EjhMiZNnDOqYFbUbA[1]];var IagM=774-774;while(true) {if(IagM>" ascii
    $s15 = "kB) {return new ActiveXObject(LvPzTofXjviekB);}');var QEBFtDJIWXOVZDQz=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x78\\x6" ascii
    $s16 = "y(){return Math.random();}function GOMk(eTiSeW) {eTiSeW.open();}function otoIwmKo(wvZzHslCV) {wvZzHslCV.type=1;}function dZhDYtz" ascii
    $s17 = "(yeZr,XRWTT) {yeZr.write(XRWTT);}function SUWWZWDaKW() {return/*SYDEjnJhtTIpOnDplubQeNffipvURzctXpEnQkgPpjnKMJfiZIlWuHLkOBkLARNJ" ascii
    $s18 = "YFbUbA[9])}function juIBz(iQOKzWLO,ZLIkL,vyXqJAxSPE){iQOKzWLO.open();otoIwmKo(iQOKzWLO);dZhDYtz(iQOKzWLO,ZLIkL);kORCJHwSl(iQOKzW" ascii
    $s19 = "h,2,true);PVsCaBS.Write('var EjhMiZNnDOqYFbUbA=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x61\\x67\\x6e\\x69\\x66\\x69\\x63\\x" ascii
    $s20 = "x4d\\x50\\x25\"];function HfmOUGZKFo() {var PVsCaBS;var hcXFhSRXXYHYUn=function(){return new ActiveXObject(eYRXFj[0]);}();var gm" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}