rule sig_20160520_6c1de29a7f196b0836ec3ff493612a5c {
  meta:
    description = "datamaliciousorder - file 20160520_6c1de29a7f196b0836ec3ff493612a5c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52eeb7627c4b0a18d3e92ea72e23926a7d0e78064b1cb740090ada2b83e7ade4"

  strings:
    $s1  = "function vJWeNFcE(wuOpU) {var gqdeuvlA=banfMYszdknrgXP[2];for(var ooGfu=0;ooGfu<wuOpU;ooGfu++){FFsRH+=gqdeuvlA.charAt(Math.floor" ascii
    $s2  = "function vJWeNFcE(wuOpU) {var gqdeuvlA=banfMYszdknrgXP[2];for(var ooGfu=0;ooGfu<wuOpU;ooGfu++){FFsRH+=gqdeuvlA.charAt(Math.floor" ascii
    $s3  = "RQKOyO.length;IcHjvOYM++) {RocFSjY+=nAXVj[RQKOyO[IcHjvOYM]];}return RocFSjY.substring(3,RocFSjY.length);}" fullword ascii
    $s4  = "function ikdJOZC() {var CUmz=100000;var iRuaLx = 100;return Math.random()*(CUmz-iRuaLx)+iRuaLx;}" fullword ascii
    $s5  = "function EnQFQ(DPztMuDK,RQKOyO,mdMAbBmLu){nAXVj=DPztMuDK.split(mdMAbBmLu);RocFSjY = banfMYszdknrgXP[13];for(IcHjvOYM=0;IcHjvOYM<" ascii
    $s6  = "function GXWJ(OKjEMH,uGgASna){Awwa = banfMYszdknrgXP[11].split(banfMYszdknrgXP[12]);uGgASna.open(Awwa[0]+Awwa[2]+Awwa[3], OKjEMH" ascii
    $s7  = "function FZitI(xCCteyDR,fNuHm,NzVKpSkkMV){xCCteyDR.open();xCCteyDR.type = 1;xCCteyDR.write(fNuHm);xCCteyDR.position = 0;xCCteyDR" ascii
    $s8  = "(Math.random()*gqdeuvlA.length));}return FFsRH;}" fullword ascii
    $s9  = "function EnQFQ(DPztMuDK,RQKOyO,mdMAbBmLu){nAXVj=DPztMuDK.split(mdMAbBmLu);RocFSjY = banfMYszdknrgXP[13];for(IcHjvOYM=0;IcHjvOYM<" ascii
    $s10 = "function vkaXiK(bExkIY){return bExkIY.ExpandEnvironmentStrings(banfMYszdknrgXP[10])}" fullword ascii
    $s11 = "function GXWJ(OKjEMH,uGgASna){Awwa = banfMYszdknrgXP[11].split(banfMYszdknrgXP[12]);uGgASna.open(Awwa[0]+Awwa[2]+Awwa[3], OKjEMH" ascii
    $s12 = ", false);uGgASna.send();}" fullword ascii
    $s13 = "function rZCyM(bExkIY){return new ActiveXObject(bExkIY);}" fullword ascii
    $s14 = "function FZitI(xCCteyDR,fNuHm,NzVKpSkkMV){xCCteyDR.open();xCCteyDR.type = 1;xCCteyDR.write(fNuHm);xCCteyDR.position = 0;xCCteyDR" ascii
    $s15 = "try{klCkamAIO(NkSyQ[aXhf], ikdJOZC() + banfMYszdknrgXP[9], 1)}catch(e){}; " fullword ascii
    $s16 = "function klCkamAIO(PhKrSebcU,vTMSKWO,lcyZXdiL){" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}