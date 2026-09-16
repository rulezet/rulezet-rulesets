rule sig_20160523_d4ece3e70803d8e092641f0aa4d78add {
  meta:
    description = "datamaliciousorder - file 20160523_d4ece3e70803d8e092641f0aa4d78add.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf580d182baa7ebee9faf4bbe9ff4f750fa5fe43930e041778632c3a413590c4"

  strings:
    $s1  = "function zMPfujwAvb() {return/*IwXUejvmqyqhIqDiJCoSSRIrcQUBFpyIoiGBEaSONPDqVamQNvZgeEaeRaOoPolisulmeQmKdiJhGpHPWwIaStnedjMIHMjsG" ascii
    $s2  = "function XZHYTRgQEN(jmODaKOY,ltpzxmsHYHKp) {jmODaKOY.Run(ltpzxmsHYHKp, 0x1, 0x0);}" fullword ascii
    $s3  = "function WVqbzXNo(RoHOn) {var SrFPAWWE=JaTRigjWy[13];for(var cUKOL=0;cUKOL<RoHOn;cUKOL++){RTqRU+=SrFPAWWE.charAt(Math.floor(Math" ascii
    $s4  = "function zMPfujwAvb() {return/*IwXUejvmqyqhIqDiJCoSSRIrcQUBFpyIoiGBEaSONPDqVamQNvZgeEaeRaOoPolisulmeQmKdiJhGpHPWwIaStnedjMIHMjsG" ascii
    $s5  = "function WVqbzXNo(RoHOn) {var SrFPAWWE=JaTRigjWy[13];for(var cUKOL=0;cUKOL<RoHOn;cUKOL++){RTqRU+=SrFPAWWE.charAt(Math.floor(Math" ascii
    $s6  = "if(cLPp>qRIoQ.length) break;" fullword ascii
    $s7  = ".random()*SrFPAWWE.length));}return RTqRU;}" fullword ascii
    $s8  = "function ZwOp(UTzCrO,vHTXrlu){mMda = JaTRigjWy[10].split(JaTRigjWy[11]);vHTXrlu.open(mMda[0]+mMda[2]+mMda[3], UTzCrO, false);vHT" ascii
    $s9  = "function NsEtt(rISSLpbc,gpIuOg,yicvTnXzw){NMvfO=rISSLpbc.split(yicvTnXzw);rlBkuvp = JaTRigjWy[12];for(rpWseEAM=0;rpWseEAM<gpIuOg" ascii
    $s10 = "function mlNCt(zhtiudQc,rZCzK,IKsdyhitEp){TOmA(zhtiudQc);HbskXIud(zhtiudQc);ewWjOSO(zhtiudQc,rZCzK);qrNRJgafY(zhtiudQc);ZASq(zht" ascii
    $s11 = "function dipfbW(iiJMJf){return iiJMJf.ExpandEnvironmentStrings(JaTRigjWy[9])}" fullword ascii
    $s12 = "function ewWjOSO(RwSq,AiNXd) {RwSq.write(AiNXd);}" fullword ascii
    $s13 = ".length;rpWseEAM++) {rlBkuvp+=NMvfO[gpIuOg[rpWseEAM]];}return rlBkuvp.substring(3,rlBkuvp.length);}" fullword ascii
    $s14 = "function ZwOp(UTzCrO,vHTXrlu){mMda = JaTRigjWy[10].split(JaTRigjWy[11]);vHTXrlu.open(mMda[0]+mMda[2]+mMda[3], UTzCrO, false);vHT" ascii
    $s15 = "function EayMdWM() {var VEpq=100000;var ClKOud = 100;return itNTdmK()*(VEpq-ClKOud)+ClKOud;}" fullword ascii
    $s16 = "function ZASq(kZRwqpg,CkiSNJJ) {kZRwqpg.saveToFile(CkiSNJJ, 2);}" fullword ascii
    $s17 = "function itNTdmK(){return Math.random();}" fullword ascii
    $s18 = "function mlNCt(zhtiudQc,rZCzK,IKsdyhitEp){TOmA(zhtiudQc);HbskXIud(zhtiudQc);ewWjOSO(zhtiudQc,rZCzK);qrNRJgafY(zhtiudQc);ZASq(zht" ascii
    $s19 = "function NsEtt(rISSLpbc,gpIuOg,yicvTnXzw){NMvfO=rISSLpbc.split(yicvTnXzw);rlBkuvp = JaTRigjWy[12];for(rpWseEAM=0;rpWseEAM<gpIuOg" ascii
    $s20 = "function usOCZDksCUbUk() {zMPfujwAvb().Sleep(2451029-334);}" fullword ascii

  condition:
    uint16(0) == 0x1b27 and
    8 of them
}