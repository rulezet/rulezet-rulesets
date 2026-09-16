rule sig_20160520_24fa528ea2f1dca22a1ac789d7d53da7 {
  meta:
    description = "datamaliciousorder - file 20160520_24fa528ea2f1dca22a1ac789d7d53da7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a84316baad6dad98b846c1e0416a574ed74bdda687763ffff1f27e356af378d"

  strings:
    $s1  = "function fViWbCMd(AEBRM) {var TARxLhhS=ITRoByPa[2];for(var autKe=0;autKe<AEBRM;autKe++){MFiNh+=TARxLhhS.charAt(Math.floor(Math.r" ascii
    $s2  = "function fViWbCMd(AEBRM) {var TARxLhhS=ITRoByPa[2];for(var autKe=0;autKe<AEBRM;autKe++){MFiNh+=TARxLhhS.charAt(Math.floor(Math.r" ascii
    $s3  = "function iTFep(YnWIDAws,SiDXDF,PDVHdNGIT){vDtJX=YnWIDAws.split(PDVHdNGIT);UIpDIgo = ITRoByPa[13];for(IUyjSywy=0;IUyjSywy<SiDXDF." ascii
    $s4  = "if (rYmgOUZ==0) break;" fullword ascii
    $s5  = "length;IUyjSywy++) {UIpDIgo+=vDtJX[SiDXDF[IUyjSywy]];}return UIpDIgo.substring(3,UIpDIgo.length);}" fullword ascii
    $s6  = "try{rYmgOUZ=XvQANfvVX(beagH[QIHs], VZXipWw() + ITRoByPa[9], 1)}catch(e){}; " fullword ascii
    $s7  = "function VZXipWw() {var CSBX=100000;var pIarrr = 100;return Math.random()*(CSBX-pIarrr)+pIarrr;}" fullword ascii
    $s8  = "function DtNLv(PzTofXjv,iekBq,tcStOqfLOd){PzTofXjv.open();PzTofXjv.type = 1;PzTofXjv.write(iekBq);PzTofXjv.position = 0;PzTofXjv" ascii
    $s9  = "andom()*TARxLhhS.length));}return MFiNh;}" fullword ascii
    $s10 = "function XvQANfvVX(sJYfnMEcV,kCQVNmT,sIyiREFi){" fullword ascii
    $s11 = "function iTFep(YnWIDAws,SiDXDF,PDVHdNGIT){vDtJX=YnWIDAws.split(PDVHdNGIT);UIpDIgo = ITRoByPa[13];for(IUyjSywy=0;IUyjSywy<SiDXDF." ascii
    $s12 = "function yjrW(LeWZbq,BRhjECn){BdNf = ITRoByPa[11].split(ITRoByPa[12]);BRhjECn.open(BdNf[0]+BdNf[2]+BdNf[3], LeWZbq, false);BRhjE" ascii
    $s13 = "function DtNLv(PzTofXjv,iekBq,tcStOqfLOd){PzTofXjv.open();PzTofXjv.type = 1;PzTofXjv.write(iekBq);PzTofXjv.position = 0;PzTofXjv" ascii
    $s14 = "function qpvjj(xjYcRo){return new ActiveXObject(xjYcRo);}" fullword ascii
    $s15 = "function hYICJC(xjYcRo){return xjYcRo.ExpandEnvironmentStrings(ITRoByPa[10])}" fullword ascii
    $s16 = "function yjrW(LeWZbq,BRhjECn){BdNf = ITRoByPa[11].split(ITRoByPa[12]);BRhjECn.open(BdNf[0]+BdNf[2]+BdNf[3], LeWZbq, false);BRhjE" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}