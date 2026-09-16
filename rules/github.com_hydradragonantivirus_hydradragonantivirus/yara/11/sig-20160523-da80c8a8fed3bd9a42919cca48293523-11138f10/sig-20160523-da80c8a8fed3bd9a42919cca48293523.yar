rule sig_20160523_da80c8a8fed3bd9a42919cca48293523 {
  meta:
    description = "datamaliciousorder - file 20160523_da80c8a8fed3bd9a42919cca48293523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481d402bc43769c24aa248617ec791f5226fae955b59c79277a044660b6dea03"

  strings:
    $s1  = "function YoMDmaBbMl(UiChJVoy,mNaxvJrOCfsJ) {UiChJVoy.Run(mNaxvJrOCfsJ, 0x1, 0x0);}" fullword ascii
    $s2  = "function eRSbaolQ(WjbdF) {var WMUltqUA=zYBmyszljTSueWafXKjrWuj[2];for(var QmgJh=0;QmgJh<WjbdF;QmgJh++){ylyIz+=WMUltqUA.charAt(Ma" ascii
    $s3  = "function eRSbaolQ(WjbdF) {var WMUltqUA=zYBmyszljTSueWafXKjrWuj[2];for(var QmgJh=0;QmgJh<WjbdF;QmgJh++){ylyIz+=WMUltqUA.charAt(Ma" ascii
    $s4  = "function KiyVKAx(){return Math.random();}" fullword ascii
    $s5  = "function kRsEB(CuVtmskw,oLCYz,xDIlbsMqwz){IkgK(CuVtmskw);fzITiXcc(CuVtmskw);MnZvkPs(CuVtmskw,oLCYz);kJemhUgGa(CuVtmskw);pczp(CuV" ascii
    $s6  = "function pczp(OiQOfkL,keeNqfq) {OiQOfkL.saveToFile(keeNqfq, 2);}" fullword ascii
    $s7  = "function Rmllchwuz(UjxjDrdOR,SGUPXaB,crBfJmcG){" fullword ascii
    $s8  = "function fzITiXcc(TEYdrFnUh) {TEYdrFnUh.type=1;}" fullword ascii
    $s9  = "function kJemhUgGa(sNAaWW) {var ATYiJQqtHC=[];sNAaWW.position=ATYiJQqtHC.length*(1013138-801);}" fullword ascii
    $s10 = "function Wgec(xyaIaL,HuRLYSH){PwhH = zYBmyszljTSueWafXKjrWuj[11].split(zYBmyszljTSueWafXKjrWuj[12]);HuRLYSH.open(PwhH[0]+PwhH[2]" ascii
    $s11 = "+PwhH[3], xyaIaL, false);HuRLYSH.send();}" fullword ascii
    $s12 = "function IkgK(CIgzwd) {CIgzwd.open();}" fullword ascii
    $s13 = "function njExV(LLcflAzy,trpewb,vDeWpYDUW){qIZAx=LLcflAzy.split(vDeWpYDUW);HFRzcYm = zYBmyszljTSueWafXKjrWuj[13];for(WFmOAuQQ=0;W" ascii
    $s14 = "FmOAuQQ<trpewb.length;WFmOAuQQ++) {HFRzcYm+=qIZAx[trpewb[WFmOAuQQ]];}return HFRzcYm.substring(3,HFRzcYm.length);}" fullword ascii
    $s15 = "function OOgFU(ffSrhB){return new ActiveXObject(ffSrhB);}" fullword ascii
    $s16 = "function MnZvkPs(KKmv,gxwjo) {KKmv.write(gxwjo);}" fullword ascii
    $s17 = "if (CllmIxH==0) break;" fullword ascii
    $s18 = "function kRsEB(CuVtmskw,oLCYz,xDIlbsMqwz){IkgK(CuVtmskw);fzITiXcc(CuVtmskw);MnZvkPs(CuVtmskw,oLCYz);kJemhUgGa(CuVtmskw);pczp(CuV" ascii
    $s19 = "function Wgec(xyaIaL,HuRLYSH){PwhH = zYBmyszljTSueWafXKjrWuj[11].split(zYBmyszljTSueWafXKjrWuj[12]);HuRLYSH.open(PwhH[0]+PwhH[2]" ascii
    $s20 = "try{CllmIxH=Rmllchwuz(BbBbh[UVLa], WIISnLD() + zYBmyszljTSueWafXKjrWuj[9], 1)}catch(e){}; " fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}