rule sig_20160524_35e75771f47620a5a6ecd13e76bca92b {
  meta:
    description = "datamaliciousorder - file 20160524_35e75771f47620a5a6ecd13e76bca92b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5a9f9df031aa57776dd0c61a3bfb20417f629281b1be8e9a9d80b99a6460921"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "R.Run(WDBmHmxhXCKN, 0x1, 0x0);}function MQdivjU() {var flQx=100000;var MMxeBe = 100;return bbEcUFn()*(flQx-MMxeBe)+MMxeBe;}funct" ascii
    $s3  = "XNNfksVCavg=function(){return new ActiveXObject(\"WScript.Shell\");}();var PlixbZFwJO = bPEjHxoLhBowSmN[1]+12856+bPEjHxoLhBowSmN" ascii
    $s4  = "DG[4]));}();var yoFunxl = vLxVad(pBwcKqNSt) + String.fromCharCode(92) + yoFunxl;var xFduW = function(){return new ActiveXObject(" ascii
    $s5  = "unxl=MQdivjU() + FxlaDG[2];var zytXEqWL=406-405;var pBwcKqNSt = function(){return new ActiveXObject(dGsWP(FxlaDG[3],[0,2,4],Fxla" ascii
    $s6  = "2]+wLxp[3], dYBIxH, false);pTlJTxf.send();}function dGsWP(mhUMWmSx,vYpcVk,ighoWNqaD){BnmWt=mhUMWmSx.split(ighoWNqaD);wgNOhvP = F" ascii
    $s7  = "dGsWP(FxlaDG[5],[0,2,4],FxlaDG[6]));}();SRFk(JOumrtCEk,xFduW);if (xFduW.status == 100+100) {var tAUnUsM = function() {return new" ascii
    $s8  = "ript;}function VDGQccjCm(wwvJCt) {var ZgNyuNTKlp=[];wwvJCt.position=ZgNyuNTKlp.length*(8135165-417);}function oACZ(PUYCOpE,jdKZE" ascii
    $s9  = "+ctDdXTpT,0x1,0x0);}Mtwzn();function (tUlDCj) {return new ActiveXObject(tUlDCj);}" fullword ascii
    $s10 = "xlaDG[12];for(DiODGVvS=0;DiODGVvS<vYpcVk.length;DiODGVvS++) {wgNOhvP+=BnmWt[vYpcVk[DiODGVvS]];}return wgNOhvP.substring(3,wgNOhv" ascii
    $s11 = "P.length);}function AxsnTrxTKRkQm() {IzTOiBbwoG().Sleep(5261-423);}function bbEcUFn(){return Math.random();}function Evdr(VaCdRI" ascii
    $s12 = ")*TebwEjsc.length));}return LobzG;}function yyKAhVBlGhbuYu(aaPtQBjpqWMUQI) {return new ActiveXObject(aaPtQBjpqWMUQI);}');var xMD" ascii
    $s13 = ");var XfzhW = [FxlaDG[0], FxlaDG[1]];var omaB=220-220;while(true) {if(omaB>XfzhW.length) break;var JOumrtCEk=XfzhW[omaB];var yoF" ascii
    $s14 = "ZD) {PUYCOpE.saveToFile(jdKZEZD, 2);}function obvTbkI(etqEi) {etqEi.close();}function SfCEFOsqkd(tRMjxeQR,WDBmHmxhXCKN) {tRMjxeQ" ascii
    $s15 = "tKyR,JWDlUJfScv);obvTbkI(HydJtKyR);}function SRFk(dYBIxH,pTlJTxf){wLxp = FxlaDG[10].split(FxlaDG[11]);pTlJTxf.open(wLxp[0]+wLxp[" ascii
    $s16 = ") {VaCdRI.open();}function HhLRvPuB(yNmjVldNr) {yNmjVldNr.type=1;}function VlNQdCg(Xuvq,SeGrf) {Xuvq.write(SeGrf);}function IzTO" ascii
    $s17 = "qkd(pBwcKqNSt,yoFunxl);} catch(e) {}break;};omaB++;}function vLxVad(xfbbJQ){return xfbbJQ.ExpandEnvironmentStrings(FxlaDG[9])}fu" ascii
    $s18 = "4\\x45\\x4d\\x50\\x25\"];function Mtwzn() {var cAjNTtYs;var dCQzXiv=function(){return new ActiveXObject(bPEjHxoLhBowSmN[0]);}();" ascii
    $s19 = "penTextFile(ctDdXTpT,2,true);cAjNTtYs.Write('var FxlaDG=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x73\\x61\\x73\\x75\\x72\\x61\\x6" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}