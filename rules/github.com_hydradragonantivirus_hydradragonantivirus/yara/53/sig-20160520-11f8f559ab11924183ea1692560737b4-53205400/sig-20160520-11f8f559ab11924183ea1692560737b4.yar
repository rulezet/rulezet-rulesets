rule sig_20160520_11f8f559ab11924183ea1692560737b4 {
  meta:
    description = "datamaliciousorder - file 20160520_11f8f559ab11924183ea1692560737b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "007357bc820019010230ef07791be3b8645abe521bbfda95cac52da790afe5f1"

  strings:
    $s1  = "function DKMdkHny(Hdejl) {var youPQwRK=hxxUjxajIadtwKvivcq[2];for(var CIMOI=0;CIMOI<Hdejl;CIMOI++){DPuGl+=youPQwRK.charAt(Math.f" ascii
    $s2  = "function DKMdkHny(Hdejl) {var youPQwRK=hxxUjxajIadtwKvivcq[2];for(var CIMOI=0;CIMOI<Hdejl;CIMOI++){DPuGl+=youPQwRK.charAt(Math.f" ascii
    $s3  = "function qSUHj(rbyFdk){return new ActiveXObject(rbyFdk);}" fullword ascii
    $s4  = "function rVAzyY(rbyFdk){return rbyFdk.ExpandEnvironmentStrings(hxxUjxajIadtwKvivcq[10])}" fullword ascii
    $s5  = "qDx<bMGjmo.length;VJjanqDx++) {umbwolf+=qmtlW[bMGjmo[VJjanqDx]];}return umbwolf.substring(3,umbwolf.length);}" fullword ascii
    $s6  = "function yHeJy(xYYoNiCm,bMGjmo,XySTLWRiJ){qmtlW=xYYoNiCm.split(XySTLWRiJ);umbwolf = hxxUjxajIadtwKvivcq[13];for(VJjanqDx=0;VJjan" ascii
    $s7  = "function bRZu(pNxoVX,QcRYPaB){XEaZ = hxxUjxajIadtwKvivcq[11].split(hxxUjxajIadtwKvivcq[12]);QcRYPaB.open(XEaZ[0]+XEaZ[2]+XEaZ[3]" ascii
    $s8  = ", pNxoVX, false);QcRYPaB.send();}" fullword ascii
    $s9  = "try{RcwILoLhI(tDveh[iHkh], PJdhACK() + hxxUjxajIadtwKvivcq[9], 1)}catch(e){}; " fullword ascii
    $s10 = "function rGiBr(uCZUmOVz,pegeh,kZhTqrGdjB){uCZUmOVz.open();uCZUmOVz.type = 1;uCZUmOVz.write(pegeh);uCZUmOVz.position = 0;uCZUmOVz" ascii
    $s11 = "function bRZu(pNxoVX,QcRYPaB){XEaZ = hxxUjxajIadtwKvivcq[11].split(hxxUjxajIadtwKvivcq[12]);QcRYPaB.open(XEaZ[0]+XEaZ[2]+XEaZ[3]" ascii
    $s12 = "loor(Math.random()*youPQwRK.length));}return DPuGl;}" fullword ascii
    $s13 = "function rGiBr(uCZUmOVz,pegeh,kZhTqrGdjB){uCZUmOVz.open();uCZUmOVz.type = 1;uCZUmOVz.write(pegeh);uCZUmOVz.position = 0;uCZUmOVz" ascii
    $s14 = "function PJdhACK() {var xWRX=100000;var JNUpVm = 100;return Math.random()*(xWRX-JNUpVm)+JNUpVm;}" fullword ascii
    $s15 = "function RcwILoLhI(vMNSowfcm,onwgmRL,oQViCWey){" fullword ascii
    $s16 = "function yHeJy(xYYoNiCm,bMGjmo,XySTLWRiJ){qmtlW=xYYoNiCm.split(XySTLWRiJ);umbwolf = hxxUjxajIadtwKvivcq[13];for(VJjanqDx=0;VJjan" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}