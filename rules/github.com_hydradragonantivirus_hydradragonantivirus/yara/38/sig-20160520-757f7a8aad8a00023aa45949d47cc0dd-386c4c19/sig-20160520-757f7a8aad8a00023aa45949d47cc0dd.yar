rule sig_20160520_757f7a8aad8a00023aa45949d47cc0dd {
  meta:
    description = "datamaliciousorder - file 20160520_757f7a8aad8a00023aa45949d47cc0dd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4712f674168f15710c49160cef21f215305fadddd7b65e41258564c659a9bf69"

  strings:
    $s1  = "function HVeKJwgM(iSkpf) {var MZIWjLLH=QnsehysPqNFer[2];for(var PhPJI=0;PhPJI<iSkpf;PhPJI++){xMcus+=MZIWjLLH.charAt(Math.floor(M" ascii
    $s2  = "function HVeKJwgM(iSkpf) {var MZIWjLLH=QnsehysPqNFer[2];for(var PhPJI=0;PhPJI<iSkpf;PhPJI++){xMcus+=MZIWjLLH.charAt(Math.floor(M" ascii
    $s3  = "aqMG.length;MNrMLLCH++) {LMiXhuJ+=WUZcL[QuaqMG[MNrMLLCH]];}return LMiXhuJ.substring(3,LMiXhuJ.length);}" fullword ascii
    $s4  = "ath.random()*MZIWjLLH.length));}return xMcus;}" fullword ascii
    $s5  = "function ZHQr(ORxqRd,hkEweRb){BbBH = QnsehysPqNFer[11].split(QnsehysPqNFer[12]);hkEweRb.open(BbBH[0]+BbBH[2]+BbBH[3], ORxqRd, fa" ascii
    $s6  = "function awkJj(aIarXGrv,SQZVR,yROzpjyUzV){aIarXGrv.open();aIarXGrv.type = 1;aIarXGrv.write(SQZVR);aIarXGrv.position = 0;aIarXGrv" ascii
    $s7  = "if (yhWXvBi==0) break;" fullword ascii
    $s8  = "function OLqwJ(BDfwmuLT,QuaqMG,jHYLYiZOE){WUZcL=BDfwmuLT.split(jHYLYiZOE);LMiXhuJ = QnsehysPqNFer[13];for(MNrMLLCH=0;MNrMLLCH<Qu" ascii
    $s9  = "function awkJj(aIarXGrv,SQZVR,yROzpjyUzV){aIarXGrv.open();aIarXGrv.type = 1;aIarXGrv.write(SQZVR);aIarXGrv.position = 0;aIarXGrv" ascii
    $s10 = "function Nrliaji() {var rCGF=100000;var IjGiRp = 100;return Math.random()*(rCGF-IjGiRp)+IjGiRp;}" fullword ascii
    $s11 = "function ZHQr(ORxqRd,hkEweRb){BbBH = QnsehysPqNFer[11].split(QnsehysPqNFer[12]);hkEweRb.open(BbBH[0]+BbBH[2]+BbBH[3], ORxqRd, fa" ascii
    $s12 = "try{yhWXvBi=edntJjevB(SwFJV[vvpc], Nrliaji() + QnsehysPqNFer[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function OLqwJ(BDfwmuLT,QuaqMG,jHYLYiZOE){WUZcL=BDfwmuLT.split(jHYLYiZOE);LMiXhuJ = QnsehysPqNFer[13];for(MNrMLLCH=0;MNrMLLCH<Qu" ascii
    $s14 = "function ITdFmJ(JDzRdG){return JDzRdG.ExpandEnvironmentStrings(QnsehysPqNFer[10])}" fullword ascii
    $s15 = "function edntJjevB(PYQQwGffI,sZMSFEX,SrxyacLA){" fullword ascii
    $s16 = "function kXQbl(JDzRdG){return new ActiveXObject(JDzRdG);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}