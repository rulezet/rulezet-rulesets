rule sig_20160524_1bd9586f1c0caf76739f814b2c8ccf39 {
  meta:
    description = "datamaliciousorder - file 20160524_1bd9586f1c0caf76739f814b2c8ccf39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c6be70fa07733c59597a17683481887e17bac686139e4d22cea91488f836263"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "YjevWiWwnADQKDzGyjHzoJBysWfjvnRLIAJIRcgfiJgIrPhvEkjWGmIsKPFmziwJllhpHpjiXmCUSuJDE*/WScript;}function DfhUwEoLS(qxEiNM) {var LlUO" ascii
    $s3  = "CuZKSrBN=function(){return new ActiveXObject(\"WScript.Shell\");}();var lrBcTCHTUncG = XOxnzcOQaKk[1]+17867+XOxnzcOQaKk[2];var X" ascii
    $s4  = "69\\x70\\x74\\x2e\\x65\\x78\\x65\\x20\"];dLAANxNYgkQmsX.Close();KDCuZKSrBN.Run(OyxjkJVH[0]+XNBfYMwpkG,0x1,0x0);}OtqHhPtfJnXAF();" ascii
    $s5  = ") + String.fromCharCode(92) + mfYkVpF;var ObDHq = function(){return new ActiveXObject(YBdiv(OYewggusiksIffbQqyATrY[5],[0,2,4],OY" ascii
    $s6  = "reak;var FplEghDIw=AOLKh[mztv];var mfYkVpF=ybTkyTp() + OYewggusiksIffbQqyATrY[2];var JafhETbJ=916-915;var ftZQaQzIy = function()" ascii
    $s7  = "ion xmugDET(qwOoe) {qwOoe.close();}function mHCaKBikdp(elcnOkRn,mLjJUSprMmTD) {elcnOkRn.Run(mLjJUSprMmTD, 0x1, 0x0);}function yb" ascii
    $s8  = "{return new ActiveXObject(YBdiv(OYewggusiksIffbQqyATrY[3],[0,2,4],OYewggusiksIffbQqyATrY[4]));}();var mfYkVpF = zsGCGQ(ftZQaQzIy" ascii
    $s9  = "StjGiw=[];qxEiNM.position=LlUOStjGiw.length*(4484158-355);}function ETvO(EHPmhzb,iMCrtru) {EHPmhzb.saveToFile(iMCrtru, 2);}funct" ascii
    $s10 = "Q,XZqxU);DfhUwEoLS(kWahCizQ);ETvO(kWahCizQ,ALUqrwyLBH);xmugDET(kWahCizQ);}function cdJe(XPVZbV,QcHTyAF){Gyep = OYewggusiksIffbQq" ascii
    $s11 = "bYHwx();var AOLKh = [OYewggusiksIffbQqyATrY[0], OYewggusiksIffbQqyATrY[1]];var mztv=778-778;while(true) {if(mztv>AOLKh.length) b" ascii
    $s12 = "ength;mdXLOOgl++) {fTSeWUJ+=krGDm[CzSnlf[mdXLOOgl]];}return fTSeWUJ.substring(3,fTSeWUJ.length);}function EDNTjJEVbYHwx() {nVilt" ascii
    $s13 = " (ZSoXoKg) {return new ActiveXObject(ZSoXoKg);}" fullword ascii
    $s14 = "];function OtqHhPtfJnXAF() {var dLAANxNYgkQmsX;var dvXpblNBTXsiut=function(){return new ActiveXObject(XOxnzcOQaKk[0]);}();var KD" ascii
    $s15 = "ATIFg().Sleep(4973-978);}function gIGBQqJ(){return Math.random();}function FQIi(pLxudH) {pLxudH.open();}function SnViGept(YKiTFz" ascii
    $s16 = "yATrY[10].split(OYewggusiksIffbQqyATrY[11]);QcHTyAF.open(Gyep[0]+Gyep[2]+Gyep[3], XPVZbV, false);QcHTyAF.send();}function YBdiv(" ascii
    $s17 = "aNN) {YKiTFzaNN.type=1;}function mOFhrXB(ZFAf,ZvUxu) {ZFAf.write(ZvUxu);}function nViltATIFg() {return/*lLUrWLKllBavPzoZTwzBkLfg" ascii
    $s18 = "tStrings(OYewggusiksIffbQqyATrY[9])}function PXKje(kWahCizQ,XZqxU,ALUqrwyLBH){kWahCizQ.open();SnViGept(kWahCizQ);mOFhrXB(kWahCiz" ascii
    $s19 = ".OpenTextFile(XNBfYMwpkG,2,true);dLAANxNYgkQmsX.Write('var OYewggusiksIffbQqyATrY=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x64\\x" ascii
    $s20 = "ewggusiksIffbQqyATrY[6]));}();cdJe(FplEghDIw,ObDHq);if (ObDHq.status == 100+100) {var ZyqBgTR = function() {return new ActiveXOb" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}