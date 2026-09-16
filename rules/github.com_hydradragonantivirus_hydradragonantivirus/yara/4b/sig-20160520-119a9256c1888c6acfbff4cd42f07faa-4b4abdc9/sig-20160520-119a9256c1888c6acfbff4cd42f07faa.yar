rule sig_20160520_119a9256c1888c6acfbff4cd42f07faa {
  meta:
    description = "datamaliciousorder - file 20160520_119a9256c1888c6acfbff4cd42f07faa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "223efa655e07c5ef480e6bb09007d3ac387567129fc51db327b986a5cde18cf4"

  strings:
    $s1  = "function XTiXxMHe(oitni) {var zQDpCXEv=yOORccpCwxBLoWceEKAW[2];for(var JmwMN=0;JmwMN<oitni;JmwMN++){HJYeH+=zQDpCXEv.charAt(Math." ascii
    $s2  = "function XTiXxMHe(oitni) {var zQDpCXEv=yOORccpCwxBLoWceEKAW[2];for(var JmwMN=0;JmwMN<oitni;JmwMN++){HJYeH+=zQDpCXEv.charAt(Math." ascii
    $s3  = "fxhH<AtbBWt.length;RGKvfxhH++) {rdptDau+=kMFdu[AtbBWt[RGKvfxhH]];}return rdptDau.substring(3,rdptDau.length);}" fullword ascii
    $s4  = "function NYRl(FBgTmk,viyVqPI){iUbI = yOORccpCwxBLoWceEKAW[11].split(yOORccpCwxBLoWceEKAW[12]);viyVqPI.open(iUbI[0]+iUbI[2]+iUbI[" ascii
    $s5  = "function qEyPsVJuk(aCxWhVXgZ,erUPXFQ,oSlaGFhc){" fullword ascii
    $s6  = "function LajyU(fklhAm){return new ActiveXObject(fklhAm);}" fullword ascii
    $s7  = "function MkDLin(fklhAm){return fklhAm.ExpandEnvironmentStrings(yOORccpCwxBLoWceEKAW[10])}" fullword ascii
    $s8  = "function NYRl(FBgTmk,viyVqPI){iUbI = yOORccpCwxBLoWceEKAW[11].split(yOORccpCwxBLoWceEKAW[12]);viyVqPI.open(iUbI[0]+iUbI[2]+iUbI[" ascii
    $s9  = "function BkfkF(mZACFKvK,MthUG,DwAMvyrbyZ){mZACFKvK.open();mZACFKvK.type = 1;mZACFKvK.write(MthUG);mZACFKvK.position = 0;mZACFKvK" ascii
    $s10 = "try{qEyPsVJuk(lJiPd[vsjW], DqCRvKH() + yOORccpCwxBLoWceEKAW[9], 1)}catch(e){}; " fullword ascii
    $s11 = "floor(Math.random()*zQDpCXEv.length));}return HJYeH;}" fullword ascii
    $s12 = "function BkfkF(mZACFKvK,MthUG,DwAMvyrbyZ){mZACFKvK.open();mZACFKvK.type = 1;mZACFKvK.write(MthUG);mZACFKvK.position = 0;mZACFKvK" ascii
    $s13 = "function JOepd(axPOQcrB,AtbBWt,vBxCHLURo){kMFdu=axPOQcrB.split(vBxCHLURo);rdptDau = yOORccpCwxBLoWceEKAW[13];for(RGKvfxhH=0;RGKv" ascii
    $s14 = "function JOepd(axPOQcrB,AtbBWt,vBxCHLURo){kMFdu=axPOQcrB.split(vBxCHLURo);rdptDau = yOORccpCwxBLoWceEKAW[13];for(RGKvfxhH=0;RGKv" ascii
    $s15 = "function DqCRvKH() {var arCV=100000;var DWCLXn = 100;return Math.random()*(arCV-DWCLXn)+DWCLXn;}" fullword ascii
    $s16 = "3], FBgTmk, false);viyVqPI.send();}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}