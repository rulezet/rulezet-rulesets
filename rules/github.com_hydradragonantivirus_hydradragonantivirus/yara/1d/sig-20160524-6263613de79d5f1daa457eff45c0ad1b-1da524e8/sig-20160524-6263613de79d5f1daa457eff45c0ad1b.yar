rule sig_20160524_6263613de79d5f1daa457eff45c0ad1b {
  meta:
    description = "datamaliciousorder - file 20160524_6263613de79d5f1daa457eff45c0ad1b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b05d70ea19b2871840f8d32818c3c4519a7e9071f3ec84a37815e7ad7530a6fd"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "var EvbxCTiVrkM=function(){return new ActiveXObject(\"WScript.Shell\");}();var RLLmOTtqpUeze = dDESvDXpJLvnjtvtELhspO[1]+17189+d" ascii
    $s3  = "fCeWUoPuGQDEUVLaOOgFUffSrhBMJFKLcKAMaiopHkRsEBCuVtmskwoLCYzxDIlbsMqwzWgecxyaIa*/WScript;}function IzoemnRml(lchwuz) {var CllmIxH" ascii
    $s4  = "74\\x2e\\x65\\x78\\x65\\x20\"];XIZZqrlWKn.Close();EvbxCTiVrkM.Run(bzAEuK[0]+JGuzwwpht,0x1,0x0);}gaZBlmDVq();function (oxmFIBShHq" ascii
    $s5  = " mcGotTD(XYVSo) {XYVSo.close();}function LxatTsXQgY(jKKhIGql,TIlbNxeVObiM) {jKKhIGql.Run(TIlbNxeVObiM, 0x1, 0x0);}function RnmLj" ascii
    $s6  = "iNQgkMVE[13];for(var oZTwz=0;oZTwz<LUrWL;oZTwz++){BkLfg+=KllBavPz.charAt(Math.floor(Math.random()*KllBavPz.length));}return BkLf" ascii
    $s7  = "true) {if(SWXv>lcnOk.length) break;var oJBysWfjv=lcnOk[SWXv];var nRLIAJI=RnmLjJU() + VIiLESwSwmliNQgkMVE[2];var RcgfiJgI=667-666" ascii
    $s8  = "JI = BXkqkY(rPhvEkjWG) + String.fromCharCode(92) + nRLIAJI;var Jllhp = function(){return new ActiveXObject(YFQIC(VIiLESwSwmliNQg" ascii
    $s9  = "\\x50\\x25\"];function gaZBlmDVq() {var XIZZqrlWKn;var IypqLIkS=function(){return new ActiveXObject(dDESvDXpJLvnjtvtELhspO[0]);}" ascii
    $s10 = "mOTtqpUeze;XIZZqrlWKn = IypqLIkS.OpenTextFile(JGuzwwpht,2,true);XIZZqrlWKn.Write('var VIiLESwSwmliNQgkMVE=[\"\\x68\\x74\\x74\\x7" ascii
    $s11 = "iNQgkMVE[10].split(VIiLESwSwmliNQgkMVE[11]);hQjaDIB.open(EVrV[0]+EVrV[2]+EVrV[3], PLEDdl, false);hQjaDIB.send();}function YFQIC(" ascii
    $s12 = "EBheRHw,CnRba);IzoemnRml(HEBheRHw);jDrd(HEBheRHw,yQnXEQZqhC);mcGotTD(HEBheRHw);}function CEpl(PLEDdl,hQjaDIB){EVrV = VIiLESwSwml" ascii
    $s13 = ";var rPhvEkjWG = function(){return new ActiveXObject(YFQIC(VIiLESwSwmliNQgkMVE[3],[0,2,4],VIiLESwSwmliNQgkMVE[4]));}();var nRLIA" ascii
    $s14 = "kMVE[5],[0,2,4],VIiLESwSwmliNQgkMVE[6]));}();CEpl(oJBysWfjv,Jllhp);if (Jllhp.status == 100+100) {var HpjiXmC = function() {retur" ascii
    $s15 = "nvironmentStrings(VIiLESwSwmliNQgkMVE[9])}function ENxop(HEBheRHw,CnRba,yQnXEQZqhC){HEBheRHw.open();XdXgeRSb(HEBheRHw);WMUltqU(H" ascii
    $s16 = "Ujx=[];lchwuz.position=CllmIxHUjx.length*(5458036-178);}function jDrd(ORSGUPX,aBcrBfJ) {ORSGUPX.saveToFile(aBcrBfJ, 2);}function" ascii
    $s17 = "oYoMDmaBbMlUiChJVoymNaxvJr*/LHuRLYSHPwhHQ();var lcnOk = [VIiLESwSwmliNQgkMVE[0], VIiLESwSwmliNQgkMVE[1]];var SWXv=467-467;while(" ascii
    $s18 = "th;PJYuZvzh++) {QrDHKeW+=qRorX[ARxgRV[PJYuZvzh]];}return QrDHKeW.substring(3,QrDHKeW.length);}function LHuRLYSHPwhHQ() {XchRKCob" ascii
    $s19 = "JU() {var SprM=100000;var mTDnVi = 100;return bBbhWII()*(SprM-mTDnVi)+mTDnVi;}function ltATIFgl(LUrWL) {var KllBavPz=VIiLESwSwml" ascii
    $s20 = ") {aolQWjbdF.type=1;}function WMUltqU(AQmg,Jhyly) {AQmg.write(Jhyly);}function XchRKCobai() {return/*nKsYqIKDjozccuMZIrUAlXVjwEn" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}