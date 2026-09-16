rule sig_20160523_4158363c2837a38463bdcf321903cf4a {
  meta:
    description = "datamaliciousorder - file 20160523_4158363c2837a38463bdcf321903cf4a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27674739202ffdc1cfa1c5b27ce326a4e79623e10939b5c7b0e97008ca805cca"

  strings:
    $s1  = "function tLOPAKEFXV(VptDQUDo,hHbsXMrXRJVE) {VptDQUDo.Run(hHbsXMrXRJVE, 0x1, 0x0);}" fullword ascii
    $s2  = "function PCvzyBcN(wWgcR) {var fOQEljaI=wGvsTFlDHvVvTpKWnnReAN[13];for(var efsIg=0;efsIg<wWgcR;efsIg++){ebSVg+=fOQEljaI.charAt(Ma" ascii
    $s3  = "function PCvzyBcN(wWgcR) {var fOQEljaI=wGvsTFlDHvVvTpKWnnReAN[13];for(var efsIg=0;efsIg<wWgcR;efsIg++){ebSVg+=fOQEljaI.charAt(Ma" ascii
    $s4  = "function cPSheNkcJK() {return/*cUNyBUuUzMmBgZHFyKKUMvzZLlcUcZQrFtBEPaixdfSexfsjlGfnKhyVuVdlkrNxauupvxSOYLlTHhWhJGDxYwnbLWkQLkvAe" ascii
    $s5  = "function ipBu(iXRrsJ,lgUBiXf){PJxx = wGvsTFlDHvVvTpKWnnReAN[10].split(wGvsTFlDHvVvTpKWnnReAN[11]);lgUBiXf.open(PJxx[0]+PJxx[2]+P" ascii
    $s6  = "th.floor(Math.random()*fOQEljaI.length));}return ebSVg;}" fullword ascii
    $s7  = "function VyYH(DXGekb) {DXGekb.open();}" fullword ascii
    $s8  = "function AYFtemJ(YVobu) {YVobu.close();}" fullword ascii
    $s9  = "function cPSheNkcJK() {return/*cUNyBUuUzMmBgZHFyKKUMvzZLlcUcZQrFtBEPaixdfSexfsjlGfnKhyVuVdlkrNxauupvxSOYLlTHhWhJGDxYwnbLWkQLkvAe" ascii
    $s10 = "function rCMoNsWl(BJBXUKYfy) {BJBXUKYfy.type=1;}" fullword ascii
    $s11 = "function qxpYGtwlH(TQNXdT) {var wlZgttAtnP=[];TQNXdT.position=wlZgttAtnP.length*(3075302-632);}" fullword ascii
    $s12 = "function ipBu(iXRrsJ,lgUBiXf){PJxx = wGvsTFlDHvVvTpKWnnReAN[10].split(wGvsTFlDHvVvTpKWnnReAN[11]);lgUBiXf.open(PJxx[0]+PJxx[2]+P" ascii
    $s13 = "function bUyURX(XnflGP){return XnflGP.ExpandEnvironmentStrings(wGvsTFlDHvVvTpKWnnReAN[9])}" fullword ascii
    $s14 = "function cuOjm(JAynmpvg,xriWpp,ZgGBhjrLx){ccLRN=JAynmpvg.split(ZgGBhjrLx);FBdcfqT = wGvsTFlDHvVvTpKWnnReAN[12];for(OaXTpuLl=0;Oa" ascii
    $s15 = "function pYEhdQu() {var jRQB=100000;var FUAzHx = 100;return AMQyNGP()*(jRQB-FUAzHx)+FUAzHx;}" fullword ascii
    $s16 = "Jxx[3], iXRrsJ, false);lgUBiXf.send();}" fullword ascii
    $s17 = "function cuOjm(JAynmpvg,xriWpp,ZgGBhjrLx){ccLRN=JAynmpvg.split(ZgGBhjrLx);FBdcfqT = wGvsTFlDHvVvTpKWnnReAN[12];for(OaXTpuLl=0;Oa" ascii
    $s18 = "function skoyF(NZNerWGP,ccwIw,gHfvyLvLKY){VyYH(NZNerWGP);rCMoNsWl(NZNerWGP);slEPcJR(NZNerWGP,ccwIw);qxpYGtwlH(NZNerWGP);tYNu(NZN" ascii
    $s19 = "function skoyF(NZNerWGP,ccwIw,gHfvyLvLKY){VyYH(NZNerWGP);rCMoNsWl(NZNerWGP);slEPcJR(NZNerWGP,ccwIw);qxpYGtwlH(NZNerWGP);tYNu(NZN" ascii
    $s20 = "XTpuLl<xriWpp.length;OaXTpuLl++) {FBdcfqT+=ccLRN[xriWpp[OaXTpuLl]];}return FBdcfqT.substring(3,FBdcfqT.length);}" fullword ascii

  condition:
    uint16(0) == 0x1827 and
    8 of them
}