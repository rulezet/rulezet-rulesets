rule sig_20160524_91aad0ede04567b82f2f0a6ffda4dd4e {
  meta:
    description = "datamaliciousorder - file 20160524_91aad0ede04567b82f2f0a6ffda4dd4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75770a684a1f3f4cb620339267600ceb6e06ce0780166c22e07885a4b71fba63"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "lyZPupjQQrs=function(){return new ActiveXObject(\"WScript.Shell\");}();var wHkkakHL = KJpYMaPZDezMdddxeELykg[1]+14892+KJpYMaPZDe" ascii
    $s3  = ";pFMRGUVCuBIUa.Close();DlyZPupjQQrs.Run(FnFzIBWJvoBDsplEGLlzMcL[0]+FvkjJVPCGNMN,0x1,0x0);}sPVjlliDp();function (fILPzl) {return " ascii
    $s4  = "XhzbNcO(SdlsPrPx,NCrNbiXCzilz) {SdlsPrPx.Run(NCrNbiXCzilz, 0x1, 0x0);}function EyAGmOp() {var PtQW=100000;var TdPmRW = 100;retur" ascii
    $s5  = "MvyrbyZNYRlFBgTmkviyVqPIiUbIVOBQGb*/WScript;}function VJukaCxWh(VXgZer) {var UPXFQoSlaG=[];VXgZer.position=UPXFQoSlaG.length*(91" ascii
    $s6  = "CiPNl++){svmqj+=FouKxGzZ.charAt(Math.floor(Math.random()*FouKxGzZ.length));}return svmqj;}function eHCqIPBpTLMxpg(BoclNLKMNmtUtR" ascii
    $s7  = "mOp() + nBVqrtsATxWeHTbbuZBVSX[2];var pkYmGRyR=712-711;var tOAKiOxnf = function(){return new ActiveXObject(tPwXI(nBVqrtsATxWeHTb" ascii
    $s8  = " nBVqrtsATxWeHTbbuZBVSX[1]];var Ycga=329-329;while(true) {if(Ycga>FPilT.length) break;var feivEETKg=FPilT[Ycga];var COurJkU=EyAG" ascii
    $s9  = "EyPs) {xsCl.write(qEyPs);}function yZmQQGGnTC() {return/*xbzLpRZFpVmiaYDUBlRMyvsjWLajyUfklhAmMkDLinfIccyzzPBkfkFmZACFKvKMthUGDwA" ascii
    $s10 = "n arCVDWC()*(PtQW-TdPmRW)+TdPmRW;}function yDhdbNMb(jhhXi) {var FouKxGzZ=nBVqrtsATxWeHTbbuZBVSX[13];for(var CiPNl=0;CiPNl<jhhXi;" ascii
    $s11 = "function sPVjlliDp() {var pFMRGUVCuBIUa;var XjkMdfSNXAC=function(){return new ActiveXObject(KJpYMaPZDezMdddxeELykg[0]);}();var D" ascii
    $s12 = "32416-726);}function FhcF(DRauEpB,MZXJSHQ) {DRauEpB.saveToFile(MZXJSHQ, 2);}function cwTqMMC(xrwYI) {xrwYI.close();}function WPb" ascii
    $s13 = " = function(){return new ActiveXObject(tPwXI(nBVqrtsATxWeHTbbuZBVSX[5],[0,2,4],nBVqrtsATxWeHTbbuZBVSX[6]));}();mJDU(feivEETKg,yf" ascii
    $s14 = "fDF);if (yffDF.status == 100+100) {var zFHoYYk = function() {return new ActiveXObject(tPwXI(nBVqrtsATxWeHTbbuZBVSX[7],[0,2,4],nB" ascii
    $s15 = "urn Math.random();}function LXnX(TiXxMH) {TiXxMH.open();}function eoitnizQ(DpCXEvJmw) {DpCXEvJmw.type=1;}function MNHJYeH(xsCl,q" ascii
    $s16 = "us]];}return iPdDqCR.substring(3,iPdDqCR.length);}function DXnnRwqCCdMAv() {yZmQQGGnTC().Sleep(3169-651);}function arCVDWC(){ret" ascii
    $s17 = "MiSPEq);cwTqMMC(WKoHFMMB);}function mJDU(CRgYZf,nhoRvAI){SCIR = nBVqrtsATxWeHTbbuZBVSX[10].split(nBVqrtsATxWeHTbbuZBVSX[11]);nho" ascii
    $s18 = ") {return new ActiveXObject(BoclNLKMNmtUtR);}');var FnFzIBWJvoBDsplEGLlzMcL=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x74\\x2e\\x65\\x7" ascii
    $s19 = ";pFMRGUVCuBIUa = XjkMdfSNXAC.OpenTextFile(FvkjJVPCGNMN,2,true);pFMRGUVCuBIUa.Write('var nBVqrtsATxWeHTbbuZBVSX=[\"\\x68\\x74\\x7" ascii
    $s20 = "RvAI.open(SCIR[0]+SCIR[2]+SCIR[3], CRgYZf, false);nhoRvAI.send();}function tPwXI(InXzdyjX,mXFGTZ,IGmysCaLh){jBblJ=InXzdyjX.split" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}