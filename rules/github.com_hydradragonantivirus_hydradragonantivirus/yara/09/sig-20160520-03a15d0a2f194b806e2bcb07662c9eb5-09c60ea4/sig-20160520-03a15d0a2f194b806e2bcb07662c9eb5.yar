rule sig_20160520_03a15d0a2f194b806e2bcb07662c9eb5 {
  meta:
    description = "datamaliciousorder - file 20160520_03a15d0a2f194b806e2bcb07662c9eb5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2a4d36a941631288cf6c1983d7f1d5dcb251121b828123b7c597813386b4055"

  strings:
    $s1  = "function ZBXkqkYG(qFYhz) {var RiENxopH=ZySoOEfDnrgvRsDHXMT[2];for(var EBheR=0;EBheR<qFYhz;EBheR++){HwCnR+=RiENxopH.charAt(Math.f" ascii
    $s2  = "function ZBXkqkYG(qFYhz) {var RiENxopH=ZySoOEfDnrgvRsDHXMT[2];for(var EBheR=0;EBheR<qFYhz;EBheR++){HwCnR+=RiENxopH.charAt(Math.f" ascii
    $s3  = "function lyIzo(emnRmllc,hwuzC,llmIxHUjxj){emnRmllc.open();emnRmllc.type = 1;emnRmllc.write(hwuzC);emnRmllc.position = 0;emnRmllc" ascii
    $s4  = "Djo<biMXch.length;sYqIKDjo++) {ZIrUAlX+=zccuM[biMXch[sYqIKDjo]];}return ZIrUAlX.substring(3,ZIrUAlX.length);}" fullword ascii
    $s5  = ", RSGUPX, false);aBcrBfJ.send();}" fullword ascii
    $s6  = "function IGqlT(IlbNxeVO,biMXch,RKCobainK){zccuM=IlbNxeVO.split(RKCobainK);ZIrUAlX = ZySoOEfDnrgvRsDHXMT[13];for(sYqIKDjo=0;sYqIK" ascii
    $s7  = "function lyIzo(emnRmllc,hwuzC,llmIxHUjxj){emnRmllc.open();emnRmllc.type = 1;emnRmllc.write(hwuzC);emnRmllc.position = 0;emnRmllc" ascii
    $s8  = "function NJKSWXv() {var gyby=100000;var AKuZkA = 100;return Math.random()*(gyby-AKuZkA)+AKuZkA;}" fullword ascii
    $s9  = "try{nXEQZqhCC(nfnMY[XgeR], NJKSWXv() + ZySoOEfDnrgvRsDHXMT[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function WMUltq(QWjbdF){return QWjbdF.ExpandEnvironmentStrings(ZySoOEfDnrgvRsDHXMT[10])}" fullword ascii
    $s11 = "function Sbaol(QWjbdF){return new ActiveXObject(QWjbdF);}" fullword ascii
    $s12 = "function DrdO(RSGUPX,aBcrBfJ){mcGo = ZySoOEfDnrgvRsDHXMT[11].split(ZySoOEfDnrgvRsDHXMT[12]);aBcrBfJ.open(mcGo[0]+mcGo[2]+mcGo[3]" ascii
    $s13 = "function DrdO(RSGUPX,aBcrBfJ){mcGo = ZySoOEfDnrgvRsDHXMT[11].split(ZySoOEfDnrgvRsDHXMT[12]);aBcrBfJ.open(mcGo[0]+mcGo[2]+mcGo[3]" ascii
    $s14 = "loor(Math.random()*RiENxopH.length));}return HwCnR;}" fullword ascii
    $s15 = "function nXEQZqhCC(EplPLEDdl,hQjaDIB,EVrVVPCK){" fullword ascii
    $s16 = "function IGqlT(IlbNxeVO,biMXch,RKCobainK){zccuM=IlbNxeVO.split(RKCobainK);ZIrUAlX = ZySoOEfDnrgvRsDHXMT[13];for(sYqIKDjo=0;sYqIK" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}