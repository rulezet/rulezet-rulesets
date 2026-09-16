rule sig_20160520_5478dd16f7b905018bd3101162744c1c {
  meta:
    description = "datamaliciousorder - file 20160520_5478dd16f7b905018bd3101162744c1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3938b2e0dcee843dac42f07101ac36b323882067f42a60f5b4359bb18eb9ba57"

  strings:
    $s1  = "function QNUkDwkZ(MDnGQ) {var nmWOgVne=quuAAoLErLqOQYvoZpUle[2];for(var nxwJl=0;nxwJl<MDnGQ;nxwJl++){GRdhF+=nmWOgVne.charAt(Math" ascii
    $s2  = "function QNUkDwkZ(MDnGQ) {var nmWOgVne=quuAAoLErLqOQYvoZpUle[2];for(var nxwJl=0;nxwJl<MDnGQ;nxwJl++){GRdhF+=nmWOgVne.charAt(Math" ascii
    $s3  = "function zSnlf(Uxuiutug,ymdXLO,OglkrGDmf){ggIGB=Uxuiutug.split(OglkrGDmf);QqJFQIi = quuAAoLErLqOQYvoZpUle[13];for(TSeWUJAi=0;TSe" ascii
    $s4  = "function yAFG(yepJVY,BYuVIZa){fBJs = quuAAoLErLqOQYvoZpUle[11].split(quuAAoLErLqOQYvoZpUle[12]);BYuVIZa.open(fBJs[0]+fBJs[2]+fBJ" ascii
    $s5  = "function PXKjek(ucWquN){return ucWquN.ExpandEnvironmentStrings(quuAAoLErLqOQYvoZpUle[10])}" fullword ascii
    $s6  = ".floor(Math.random()*nmWOgVne.length));}return GRdhF;}" fullword ascii
    $s7  = "function yAFG(yepJVY,BYuVIZa){fBJs = quuAAoLErLqOQYvoZpUle[11].split(quuAAoLErLqOQYvoZpUle[12]);BYuVIZa.open(fBJs[0]+fBJs[2]+fBJ" ascii
    $s8  = "s[3], yepJVY, false);BYuVIZa.send();}" fullword ascii
    $s9  = "function hDIwmfYkV(pFJafhETb,JftZQaQ,zIydzOmx){" fullword ascii
    $s10 = "function CGQIr(ucWquN){return new ActiveXObject(ucWquN);}" fullword ascii
    $s11 = "function ZqxUA(LUqrwyLB,HcdJe,XPVZbVQcHT){LUqrwyLB.open();LUqrwyLB.type = 1;LUqrwyLB.write(HcdJe);LUqrwyLB.position = 0;LUqrwyLB" ascii
    $s12 = "function ZqxUA(LUqrwyLB,HcdJe,XPVZbVQcHT){LUqrwyLB.open();LUqrwyLB.type = 1;LUqrwyLB.write(HcdJe);LUqrwyLB.position = 0;LUqrwyLB" ascii
    $s13 = "function lqzfZak() {var JUnZ=100000;var fmBZFU = 100;return Math.random()*(JUnZ-fmBZFU)+fmBZFU;}" fullword ascii
    $s14 = "WUJAi<ymdXLO.length;TSeWUJAi++) {QqJFQIi+=ggIGB[ymdXLO[TSeWUJAi]];}return QqJFQIi.substring(3,QqJFQIi.length);}" fullword ascii
    $s15 = "try{hDIwmfYkV(jKlpJ[YzsG], lqzfZak() + quuAAoLErLqOQYvoZpUle[9], 1)}catch(e){}; " fullword ascii
    $s16 = "function zSnlf(Uxuiutug,ymdXLO,OglkrGDmf){ggIGB=Uxuiutug.split(OglkrGDmf);QqJFQIi = quuAAoLErLqOQYvoZpUle[13];for(TSeWUJAi=0;TSe" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}