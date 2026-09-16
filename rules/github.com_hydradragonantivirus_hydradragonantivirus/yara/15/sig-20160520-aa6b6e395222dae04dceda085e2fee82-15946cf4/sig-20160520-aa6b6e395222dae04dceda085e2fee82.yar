rule sig_20160520_aa6b6e395222dae04dceda085e2fee82 {
  meta:
    description = "datamaliciousorder - file 20160520_aa6b6e395222dae04dceda085e2fee82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aad70f98f895a10f77bf0fabbf4961c5bd7caff7e147ee6f8ef38979d2e0db01"

  strings:
    $s1  = "function xdaC(CoXnIg,zcsrasN){gqix = zYyyTDnhZooUDDRW[11].split(zYyyTDnhZooUDDRW[12]);zcsrasN.open(gqix[0]+gqix[2]+gqix[3], CoXn" ascii
    $s2  = "function xdaC(CoXnIg,zcsrasN){gqix = zYyyTDnhZooUDDRW[11].split(zYyyTDnhZooUDDRW[12]);zcsrasN.open(gqix[0]+gqix[2]+gqix[3], CoXn" ascii
    $s3  = "function PAzErxTq(gwqWH) {var CaqRuKNj=zYyyTDnhZooUDDRW[2];for(var cEhIf=0;cEhIf<gwqWH;cEhIf++){tPLJq+=CaqRuKNj.charAt(Math.floo" ascii
    $s4  = "function PAzErxTq(gwqWH) {var CaqRuKNj=zYyyTDnhZooUDDRW[2];for(var cEhIf=0;cEhIf<gwqWH;cEhIf++){tPLJq+=CaqRuKNj.charAt(Math.floo" ascii
    $s5  = "function cfQQL(YdmnxBwM,McuME,XCukfVnoRV){YdmnxBwM.open();YdmnxBwM.type = 1;YdmnxBwM.write(McuME);YdmnxBwM.position = 0;YdmnxBwM" ascii
    $s6  = "function qBwwu(emhzwS){return new ActiveXObject(emhzwS);}" fullword ascii
    $s7  = "function LRfSh(itXPBJYj,anKnlQ,CznDpRKnq){PWzYr=itXPBJYj.split(CznDpRKnq);YcBqTFD = zYyyTDnhZooUDDRW[13];for(OHdyoKMd=0;OHdyoKMd" ascii
    $s8  = "function PZlarHTIA(OvsjqwOJO,ahSfMjc,PMfgOEHu){" fullword ascii
    $s9  = "function LRfSh(itXPBJYj,anKnlQ,CznDpRKnq){PWzYr=itXPBJYj.split(CznDpRKnq);YcBqTFD = zYyyTDnhZooUDDRW[13];for(OHdyoKMd=0;OHdyoKMd" ascii
    $s10 = "Ig, false);zcsrasN.send();}" fullword ascii
    $s11 = "<anKnlQ.length;OHdyoKMd++) {YcBqTFD+=PWzYr[anKnlQ[OHdyoKMd]];}return YcBqTFD.substring(3,YcBqTFD.length);}" fullword ascii
    $s12 = "function QlLzmxx() {var UQdS=100000;var yWBavu = 100;return Math.random()*(UQdS-yWBavu)+yWBavu;}" fullword ascii
    $s13 = "try{PZlarHTIA(RNtcC[miKb], QlLzmxx() + zYyyTDnhZooUDDRW[9], 1)}catch(e){}; " fullword ascii
    $s14 = "function AcHytc(emhzwS){return emhzwS.ExpandEnvironmentStrings(zYyyTDnhZooUDDRW[10])}" fullword ascii
    $s15 = "function cfQQL(YdmnxBwM,McuME,XCukfVnoRV){YdmnxBwM.open();YdmnxBwM.type = 1;YdmnxBwM.write(McuME);YdmnxBwM.position = 0;YdmnxBwM" ascii
    $s16 = "r(Math.random()*CaqRuKNj.length));}return tPLJq;}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}