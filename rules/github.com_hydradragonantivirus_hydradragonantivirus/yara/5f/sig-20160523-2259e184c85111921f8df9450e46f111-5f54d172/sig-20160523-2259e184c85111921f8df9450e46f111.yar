rule sig_20160523_2259e184c85111921f8df9450e46f111 {
  meta:
    description = "datamaliciousorder - file 20160523_2259e184c85111921f8df9450e46f111.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "347d1087aab4bf36e483904464b75aedcd210a3f3436a9a5add20ed75c46e049"

  strings:
    $s1  = "function JHbChtDqrH(IyNBBTsH,SSFeUozwsxyP) {IyNBBTsH.Run(SSFeUozwsxyP, 0x1, 0x0);}" fullword ascii
    $s2  = "function SVwTveCU(irXWJ) {var tZvfxCsZ=PXQeROS[13];for(var mVjwY=0;mVjwY<irXWJ;mVjwY++){YUcuc+=tZvfxCsZ.charAt(Math.floor(Math.r" ascii
    $s3  = "function SVwTveCU(irXWJ) {var tZvfxCsZ=PXQeROS[13];for(var mVjwY=0;mVjwY<irXWJ;mVjwY++){YUcuc+=tZvfxCsZ.charAt(Math.floor(Math.r" ascii
    $s4  = "function KTREF(ONbYDJWO,QsJzHY,gdHnDZTwU){aEZYY=ONbYDJWO.split(gdHnDZTwU);PUjhmpY = PXQeROS[12];for(lYlvmbRZ=0;lYlvmbRZ<QsJzHY.l" ascii
    $s5  = "function olfJSWi() {var aEyv=100000;var nwvEPT = 100;return kuHWkWq()*(aEyv-nwvEPT)+nwvEPT;}" fullword ascii
    $s6  = "function rIeII(Cpxkdo){return new ActiveXObject(Cpxkdo);}" fullword ascii
    $s7  = "function MCwL(hMimUd,EbeKDeq){uxRJ = PXQeROS[10].split(PXQeROS[11]);EbeKDeq.open(uxRJ[0]+uxRJ[2]+uxRJ[3], hMimUd, false);EbeKDeq" ascii
    $s8  = "function MCwL(hMimUd,EbeKDeq){uxRJ = PXQeROS[10].split(PXQeROS[11]);EbeKDeq.open(uxRJ[0]+uxRJ[2]+uxRJ[3], hMimUd, false);EbeKDeq" ascii
    $s9  = "function eQBE(FtHCKN) {FtHCKN.open();}" fullword ascii
    $s10 = "function HnYKIWj(raSpR) {raSpR.close();}" fullword ascii
    $s11 = "function kuHWkWq(){return Math.random();}" fullword ascii
    $s12 = "function yWQMeq(Cpxkdo){return Cpxkdo.ExpandEnvironmentStrings(PXQeROS[9])}" fullword ascii
    $s13 = "if(Nqvo>Wumbw.length) break;" fullword ascii
    $s14 = "function bykNgGf(KDTL,WxxUv) {KDTL.write(WxxUv);}" fullword ascii
    $s15 = "function oPeoSwZP(tbgGqKLIF) {tbgGqKLIF.type=1;}" fullword ascii
    $s16 = "function axfL(dvxqWbm,PPhzMve) {dvxqWbm.saveToFile(PPhzMve, 2);}" fullword ascii
    $s17 = "ength;lYlvmbRZ++) {PUjhmpY+=aEZYY[QsJzHY[lYlvmbRZ]];}return PUjhmpY.substring(3,PUjhmpY.length);}" fullword ascii
    $s18 = "andom()*tZvfxCsZ.length));}return YUcuc;}" fullword ascii
    $s19 = "function tdYGvYOAk(RIBOVz) {var KPUExpbONV=[];RIBOVz.position=KPUExpbONV.length*(8285238-276);}" fullword ascii
    $s20 = "function RLsDv(pMnJxWwn,VnEkT,EIfdmieLeb){eQBE(pMnJxWwn);oPeoSwZP(pMnJxWwn);bykNgGf(pMnJxWwn,VnEkT);tdYGvYOAk(pMnJxWwn);axfL(pMn" ascii

  condition:
    uint16(0) == 0x0e27 and
    8 of them
}