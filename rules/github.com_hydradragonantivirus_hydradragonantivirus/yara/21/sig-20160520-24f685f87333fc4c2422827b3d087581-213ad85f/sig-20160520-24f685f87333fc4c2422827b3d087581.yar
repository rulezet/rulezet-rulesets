rule sig_20160520_24f685f87333fc4c2422827b3d087581 {
  meta:
    description = "datamaliciousorder - file 20160520_24f685f87333fc4c2422827b3d087581.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bdfd091ca3f3b16864f384e51a572104be27aa796896e276d1d9bab1d5a8415"

  strings:
    $s1  = "function IXuqjHjW(LuTnu) {var vqnPvRva=UqFkZtXzGLgjzjEtg[2];for(var FoKHL=0;FoKHL<LuTnu;FoKHL++){ZEOYQ+=vqnPvRva.charAt(Math.flo" ascii
    $s2  = "function IXuqjHjW(LuTnu) {var vqnPvRva=UqFkZtXzGLgjzjEtg[2];for(var FoKHL=0;FoKHL<LuTnu;FoKHL++){ZEOYQ+=vqnPvRva.charAt(Math.flo" ascii
    $s3  = "function ehEe(GhgNOM,LbpqRZu){KxmO = UqFkZtXzGLgjzjEtg[11].split(UqFkZtXzGLgjzjEtg[12]);LbpqRZu.open(KxmO[0]+KxmO[2]+KxmO[3], Gh" ascii
    $s4  = "function aDIgT(hRFPNVPS,HLJGBF,LlEwUmEAH){iNsGN=hRFPNVPS.split(LlEwUmEAH);GYwlzdJ = UqFkZtXzGLgjzjEtg[13];for(MLLXsKup=0;MLLXsKu" ascii
    $s5  = "try{zxoKXInXT(jzuwr[nroZ], hGKPkWv() + UqFkZtXzGLgjzjEtg[9], 1)}catch(e){}; " fullword ascii
    $s6  = "function XAjqg(QvvVswxA,WjbIU,imEfrIZVhw){QvvVswxA.open();QvvVswxA.type = 1;QvvVswxA.write(WjbIU);QvvVswxA.position = 0;QvvVswxA" ascii
    $s7  = "gNOM, false);LbpqRZu.send();}" fullword ascii
    $s8  = "function ehEe(GhgNOM,LbpqRZu){KxmO = UqFkZtXzGLgjzjEtg[11].split(UqFkZtXzGLgjzjEtg[12]);LbpqRZu.open(KxmO[0]+KxmO[2]+KxmO[3], Gh" ascii
    $s9  = "or(Math.random()*vqnPvRva.length));}return ZEOYQ;}" fullword ascii
    $s10 = "function juNUp(ABPkwX){return new ActiveXObject(ABPkwX);}" fullword ascii
    $s11 = "function zxoKXInXT(NnJmrZmBy,IzIOaMh,rnTXMflB){" fullword ascii
    $s12 = "function XAjqg(QvvVswxA,WjbIU,imEfrIZVhw){QvvVswxA.open();QvvVswxA.type = 1;QvvVswxA.write(WjbIU);QvvVswxA.position = 0;QvvVswxA" ascii
    $s13 = "function hGKPkWv() {var xGUp=100000;var FUFDhY = 100;return Math.random()*(xGUp-FUFDhY)+FUFDhY;}" fullword ascii
    $s14 = "function aDIgT(hRFPNVPS,HLJGBF,LlEwUmEAH){iNsGN=hRFPNVPS.split(LlEwUmEAH);GYwlzdJ = UqFkZtXzGLgjzjEtg[13];for(MLLXsKup=0;MLLXsKu" ascii
    $s15 = "p<HLJGBF.length;MLLXsKup++) {GYwlzdJ+=iNsGN[HLJGBF[MLLXsKup]];}return GYwlzdJ.substring(3,GYwlzdJ.length);}" fullword ascii
    $s16 = "function iZtTYn(ABPkwX){return ABPkwX.ExpandEnvironmentStrings(UqFkZtXzGLgjzjEtg[10])}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}