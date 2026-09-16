rule sig_20160524_455b3a07b3c0594409227427bece84ba {
  meta:
    description = "datamaliciousorder - file 20160524_455b3a07b3c0594409227427bece84ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "185f0ee967aef604166400a36e238b77bc23aa80a40d65e6d0d5a408769b1e0c"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "TPTazceTFUzJW[0]);}();var XjcSxt=function(){return new ActiveXObject(\"WScript.Shell\");}();var guuiVli = gBiTPTazceTFUzJW[1]+16" ascii
    $s3  = "t) {DGPxMXbC.Run(BycEhcQipbPt, 0x1, 0x0);}function xNxtIxX() {var mhEO=100000;var ITNIZq = 100;return LygFAaH()*(mhEO-ITNIZq)+IT" ascii
    $s4  = "uRwGUA*/WScript;}function pSACKdlcx(tISIaH) {var UUKAHnIhfr=[];tISIaH.position=UUKAHnIhfr.length*(3830645-245);}function ERKm(Ly" ascii
    $s5  = "NIZq;}function dPcxeVjM(Wmnhj) {var yEhXScLQ=FYmodX[13];for(var eYpSv=0;eYpSv<Wmnhj;eYpSv++){jUKAc+=yEhXScLQ.charAt(Math.floor(M" ascii
    $s6  = "0,2,4],FYmodX[4]));}();var bmzxjsh = cfkVkm(XRWyiwpBx) + String.fromCharCode(92) + bmzxjsh;var pRpXn = function(){return new Act" ascii
    $s7  = "CY];var bmzxjsh=xNxtIxX() + FYmodX[2];var qCWtQmmc=433-432;var XRWyiwpBx = function(){return new ActiveXObject(chlur(FYmodX[3],[" ascii
    $s8  = "ath.random()*yEhXScLQ.length));}return jUKAc;}function JXdiqReMAQXOLZ(TgWYFgGQsFMhRV) {return new ActiveXObject(TgWYFgGQsFMhRV);" ascii
    $s9  = "modX[9])}function VYRBY(znyrLfbG,tMKVI,YvQpiIuBiv){znyrLfbG.open();gvQZlubw(znyrLfbG);QlruNjH(znyrLfbG,tMKVI);pSACKdlcx(znyrLfbG" ascii
    $s10 = "ECMt(dhgxlj) {dhgxlj.open();}function gvQZlubw(tYFQdnOZm) {tYFQdnOZm.type=1;}function QlruNjH(zIuq,YIbhR) {zIuq.write(YIbhR);}fu" ascii
    $s11 = "\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function QFttvy() {var lgfezgqePSmJdy;var OFaIewYZIQRv=function(){return new ActiveX" ascii
    $s12 = "iveXObject(chlur(FYmodX[5],[0,2,4],FYmodX[6]));}();obqg(HCfdrAUeP,pRpXn);if (pRpXn.status == 100+100) {var cRnBIxc = function() " ascii
    $s13 = "XWUthkYBDf();var vdwcl = [FYmodX[0], FYmodX[1]];var iCCY=934-934;while(true) {if(iCCY>vdwcl.length) break;var HCfdrAUeP=vdwcl[iC" ascii
    $s14 = ");ERKm(znyrLfbG,YvQpiIuBiv);AwhIvrd(znyrLfbG);}function obqg(BdxNNr,WQccDma){VMAL = FYmodX[10].split(FYmodX[11]);WQccDma.open(VM" ascii
    $s15 = "AL[0]+VMAL[2]+VMAL[3], BdxNNr, false);WQccDma.send();}function chlur(OrgkVFXH,hKmfDU,RDPTdAUTP){pVHTO=OrgkVFXH.split(RDPTdAUTP);" ascii
    $s16 = "qIRmeoAPLjA,0x1,0x0);}QFttvy();function (CKSoWCNeTcb) {return new ActiveXObject(CKSoWCNeTcb);}" fullword ascii
    $s17 = "ezgqePSmJdy = OFaIewYZIQRv.OpenTextFile(XqqIRmeoAPLjA,2,true);lgfezgqePSmJdy.Write('var FYmodX=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f" ascii
    $s18 = "yTZDTLr = FYmodX[12];for(TyFthFoF=0;TyFthFoF<hKmfDU.length;TyFthFoF++) {yTZDTLr+=pVHTO[hKmfDU[TyFthFoF]];}return yTZDTLr.substri" ascii
    $s19 = "{return new ActiveXObject(chlur(FYmodX[7],[0,2,4],FYmodX[8]));}();VYRBY(cRnBIxc,pRpXn.ResponseBody,bmzxjsh);}if (qCWtQmmc > 0){t" ascii
    $s20 = "ng(3,yTZDTLr.length);}function krFXWUthkYBDf() {lmXPGbOCLn().Sleep(5087-257);}function LygFAaH(){return Math.random();}function " ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}