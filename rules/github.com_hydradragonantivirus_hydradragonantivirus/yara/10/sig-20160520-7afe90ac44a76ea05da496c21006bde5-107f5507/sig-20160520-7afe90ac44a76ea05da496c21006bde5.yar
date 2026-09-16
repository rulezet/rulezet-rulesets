rule sig_20160520_7afe90ac44a76ea05da496c21006bde5 {
  meta:
    description = "datamaliciousorder - file 20160520_7afe90ac44a76ea05da496c21006bde5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d27f53b87d66e7f5e6de43874657ed5baff8f7538448aaeccf9bc2c498d04b6f"

  strings:
    $s1  = "function HPhkuxWc(hwZOO) {var LVgGPNpA=pqqBsAoTP[2];for(var GhbPI=0;GhbPI<hwZOO;GhbPI++){iAqUv+=LVgGPNpA.charAt(Math.floor(Math." ascii
    $s2  = "function HPhkuxWc(hwZOO) {var LVgGPNpA=pqqBsAoTP[2];for(var GhbPI=0;GhbPI<hwZOO;GhbPI++){iAqUv+=LVgGPNpA.charAt(Math.floor(Math." ascii
    $s3  = "function fBNfPFM() {var Qosi=100000;var vOEbza = 100;return Math.random()*(Qosi-vOEbza)+vOEbza;}" fullword ascii
    $s4  = "function gYoxloTWW(kBaaeLOJO,uRGFcoe,wHKPEGjW){" fullword ascii
    $s5  = "function rAlGs(GSYOPWAE,GkCll,RXJiEdvCIM){GSYOPWAE.open();GSYOPWAE.type = 1;GSYOPWAE.write(GkCll);GSYOPWAE.position = 0;GSYOPWAE" ascii
    $s6  = "function rAlGs(GSYOPWAE,GkCll,RXJiEdvCIM){GSYOPWAE.open();GSYOPWAE.type = 1;GSYOPWAE.write(GkCll);GSYOPWAE.position = 0;GSYOPWAE" ascii
    $s7  = "function qweGc(tmHCvv){return new ActiveXObject(tmHCvv);}" fullword ascii
    $s8  = ".length;LrmEkejg++) {WUJfyrH+=gxbeP[ImMUFy[LrmEkejg]];}return WUJfyrH.substring(3,WUJfyrH.length);}" fullword ascii
    $s9  = "random()*LVgGPNpA.length));}return iAqUv;}" fullword ascii
    $s10 = "function qIzjrL(tmHCvv){return tmHCvv.ExpandEnvironmentStrings(pqqBsAoTP[10])}" fullword ascii
    $s11 = "function vfrjB(GBVJzXBJ,ImMUFy,PiqmuQlGM){gxbeP=GBVJzXBJ.split(PiqmuQlGM);WUJfyrH = pqqBsAoTP[13];for(LrmEkejg=0;LrmEkejg<ImMUFy" ascii
    $s12 = "try{gYoxloTWW(wAMPj[bfRb], fBNfPFM() + pqqBsAoTP[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function vfrjB(GBVJzXBJ,ImMUFy,PiqmuQlGM){gxbeP=GBVJzXBJ.split(PiqmuQlGM);WUJfyrH = pqqBsAoTP[13];for(LrmEkejg=0;LrmEkejg<ImMUFy" ascii
    $s14 = "function uXPq(eAjGyO,CaaTgrI){uFVV = pqqBsAoTP[11].split(pqqBsAoTP[12]);CaaTgrI.open(uFVV[0]+uFVV[2]+uFVV[3], eAjGyO, false);Caa" ascii
    $s15 = "function uXPq(eAjGyO,CaaTgrI){uFVV = pqqBsAoTP[11].split(pqqBsAoTP[12]);CaaTgrI.open(uFVV[0]+uFVV[2]+uFVV[3], eAjGyO, false);Caa" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}