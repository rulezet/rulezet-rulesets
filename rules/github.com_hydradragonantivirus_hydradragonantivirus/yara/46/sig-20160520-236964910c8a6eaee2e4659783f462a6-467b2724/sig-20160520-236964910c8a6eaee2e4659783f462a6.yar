rule sig_20160520_236964910c8a6eaee2e4659783f462a6 {
  meta:
    description = "datamaliciousorder - file 20160520_236964910c8a6eaee2e4659783f462a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b29c5ba1ccbe82a106ac5532885d91856d5a3304bdd57cdbfa97e1abadeaecf"

  strings:
    $s1  = "function QoILZ(tjAQGmiv,oHFrbN,sLfwrhmZb){dDbFD=tjAQGmiv.split(sLfwrhmZb);cFSEJqI = ebiKc[13];for(KGpvYZKX=0;KGpvYZKX<oHFrbN.len" ascii
    $s2  = "function ToLmvVSY(iUvOt) {var crlNKfxB=ebiKc[2];for(var MJavz=0;MJavz<iUvOt;MJavz++){CaGOH+=crlNKfxB.charAt(Math.floor(Math.rand" ascii
    $s3  = "function ToLmvVSY(iUvOt) {var crlNKfxB=ebiKc[2];for(var MJavz=0;MJavz<iUvOt;MJavz++){CaGOH+=crlNKfxB.charAt(Math.floor(Math.rand" ascii
    $s4  = "function CwQpY(dXAOGs){return new ActiveXObject(dXAOGs);}" fullword ascii
    $s5  = "if (DTwZjeP==0) break;" fullword ascii
    $s6  = "function VctRr(yJFALUWG,HYvvF,uievgNtwHp){yJFALUWG.open();yJFALUWG.type = 1;yJFALUWG.write(HYvvF);yJFALUWG.position = 0;yJFALUWG" ascii
    $s7  = "function mtVYhTWHS(GWvMsCkKp,mpIaLcf,FloYJxrM){" fullword ascii
    $s8  = "function rfqTKB(dXAOGs){return dXAOGs.ExpandEnvironmentStrings(ebiKc[10])}" fullword ascii
    $s9  = "gth;KGpvYZKX++) {cFSEJqI+=dDbFD[oHFrbN[KGpvYZKX]];}return cFSEJqI.substring(3,cFSEJqI.length);}" fullword ascii
    $s10 = "function QoILZ(tjAQGmiv,oHFrbN,sLfwrhmZb){dDbFD=tjAQGmiv.split(sLfwrhmZb);cFSEJqI = ebiKc[13];for(KGpvYZKX=0;KGpvYZKX<oHFrbN.len" ascii
    $s11 = "try{DTwZjeP=mtVYhTWHS(dcdEg[YZFj], RlKoHax() + ebiKc[9], 1)}catch(e){}; " fullword ascii
    $s12 = "function VctRr(yJFALUWG,HYvvF,uievgNtwHp){yJFALUWG.open();yJFALUWG.type = 1;yJFALUWG.write(HYvvF);yJFALUWG.position = 0;yJFALUWG" ascii
    $s13 = "function RlKoHax() {var Abhh=100000;var ngTHAz = 100;return Math.random()*(Abhh-ngTHAz)+ngTHAz;}" fullword ascii
    $s14 = "function zBVt(hZueDK,caxatnd){Mqwe = ebiKc[11].split(ebiKc[12]);caxatnd.open(Mqwe[0]+Mqwe[2]+Mqwe[3], hZueDK, false);caxatnd.sen" ascii
    $s15 = "om()*crlNKfxB.length));}return CaGOH;}" fullword ascii
    $s16 = "function zBVt(hZueDK,caxatnd){Mqwe = ebiKc[11].split(ebiKc[12]);caxatnd.open(Mqwe[0]+Mqwe[2]+Mqwe[3], hZueDK, false);caxatnd.sen" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}