rule sig_20160523_9d975f4780946cccafe9b672f7832cd0 {
  meta:
    description = "datamaliciousorder - file 20160523_9d975f4780946cccafe9b672f7832cd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a1bffd23012adbbbd1696329e9077c5b33379be26251173747ea225f6ba04eb"

  strings:
    $s1  = "function WteWzRAEXN(XhPPFpce,bLMUZhrrMrnk) {XhPPFpce.Run(bLMUZhrrMrnk, 0x1, 0x0);}" fullword ascii
    $s2  = "function qzdJsbPI(fFKeX) {var ExMcsYpa=zbcbOMP[13];for(var Oimhi=0;Oimhi<fFKeX;Oimhi++){XEwOb+=ExMcsYpa.charAt(Math.floor(Math.r" ascii
    $s3  = "function qzdJsbPI(fFKeX) {var ExMcsYpa=zbcbOMP[13];for(var Oimhi=0;Oimhi<fFKeX;Oimhi++){XEwOb+=ExMcsYpa.charAt(Math.floor(Math.r" ascii
    $s4  = "function rwRfJUQeCy() {return/*YOuXUttxrCVsqxOLtTOXgQQYBNRrcugJcwBWHohGwXWXfsTzCanIBppImSiOcxthKvDNrYNCvrfEZdenJwpppuQHSZgVPAPCg" ascii
    $s5  = "function bvLRBA(qWBFSX){return qWBFSX.ExpandEnvironmentStrings(zbcbOMP[9])}" fullword ascii
    $s6  = "function eljELPp(){return Math.random();}" fullword ascii
    $s7  = "function FywJD(lWzVsyyl,gaWZi,CFzINfFJqB){QTuz(lWzVsyyl);Tdvvqpbt(lWzVsyyl);MpqPiEr(lWzVsyyl,gaWZi);aURtuNbYP(lWzVsyyl);touw(lWz" ascii
    $s8  = "function Tvadw(oLsnCUYJ,unHlyx,QXkjvzEVK){arVrw=oLsnCUYJ.split(QXkjvzEVK);XaGRiAr = zbcbOMP[12];for(vxlDSCOD=0;vxlDSCOD<unHlyx.l" ascii
    $s9  = "function Tdvvqpbt(rZmHkstoj) {rZmHkstoj.type=1;}" fullword ascii
    $s10 = "andom()*ExMcsYpa.length));}return XEwOb;}" fullword ascii
    $s11 = "function FywJD(lWzVsyyl,gaWZi,CFzINfFJqB){QTuz(lWzVsyyl);Tdvvqpbt(lWzVsyyl);MpqPiEr(lWzVsyyl,gaWZi);aURtuNbYP(lWzVsyyl);touw(lWz" ascii
    $s12 = "function TmBx(ZMmBRs,UZkGRCu){dyzQ = zbcbOMP[10].split(zbcbOMP[11]);UZkGRCu.open(dyzQ[0]+dyzQ[2]+dyzQ[3], ZMmBRs, false);UZkGRCu" ascii
    $s13 = "if(uUBT>AGrPd.length) break;" fullword ascii
    $s14 = "function PvIeFHEoTYVwt() {rwRfJUQeCy().Sleep(2435343-799);}" fullword ascii
    $s15 = "function aURtuNbYP(Ynkzen) {var wtTGConpla=[];Ynkzen.position=wtTGConpla.length*(3651179-808);}" fullword ascii
    $s16 = "function mkZYCSk() {var UOCt=100000;var CtiEYs = 100;return eljELPp()*(UOCt-CtiEYs)+CtiEYs;}" fullword ascii
    $s17 = "function TmBx(ZMmBRs,UZkGRCu){dyzQ = zbcbOMP[10].split(zbcbOMP[11]);UZkGRCu.open(dyzQ[0]+dyzQ[2]+dyzQ[3], ZMmBRs, false);UZkGRCu" ascii
    $s18 = "function DKeMkLU(qmmmM) {qmmmM.close();}" fullword ascii
    $s19 = "ength;vxlDSCOD++) {XaGRiAr+=arVrw[unHlyx[vxlDSCOD]];}return XaGRiAr.substring(3,XaGRiAr.length);}" fullword ascii
    $s20 = "function touw(qVgKVho,Fvkjzgk) {qVgKVho.saveToFile(Fvkjzgk, 2);}" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}