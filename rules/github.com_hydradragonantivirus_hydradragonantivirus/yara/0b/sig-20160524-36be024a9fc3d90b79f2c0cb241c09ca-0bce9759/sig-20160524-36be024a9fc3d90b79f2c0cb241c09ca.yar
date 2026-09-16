rule sig_20160524_36be024a9fc3d90b79f2c0cb241c09ca {
  meta:
    description = "datamaliciousorder - file 20160524_36be024a9fc3d90b79f2c0cb241c09ca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a190a9bb9b4549f5a1ba79a2a70557909ef935feb1e9f6fae2321df8f748e522"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "){return new ActiveXObject(iYnREU[0]);}();var upBlvTK=function(){return new ActiveXObject(\"WScript.Shell\");}();var jPdLl = iYn" ascii
    $s3  = "65\\x78\\x65\\x20\"];EqxRVMQNj.Close();upBlvTK.Run(SESNGWigB[0]+qGKHWSf,0x1,0x0);}EpagjpM();function (jUxLK) {return new ActiveX" ascii
    $s4  = "zhvEPyihXDqcUaDIgThRFPNVPSHLJGBFLlEwUmEAHMLLXsKupiNsGNGYwlzdJjfaQJ*/WScript;}function DBSCNjsBv(bkjltV) {var EwfwrNBlBu=[];bkjlt" ascii
    $s5  = "NU) {ZjuNU.close();}function pABPkwXiZt(TYncGJeI,cndXAjqgQvvV) {TYncGJeI.Run(cndXAjqgQvvV, 0x1, 0x0);}function PEbULvp() {var wp" ascii
    $s6  = "];for(var gBdSy=0;gBdSy<bSKWi;gBdSy++){BQlWe+=VRXodgPF.charAt(Math.floor(Math.random()*VRXodgPF.length));}return BQlWe;}function" ascii
    $s7  = "ngth) break;var nIrzkhlft=WWkWL[EbTf];var AYavzWL=PEbULvp() + GmkwkHXVVIhodkpjDwyj[2];var uoXiVGsR=695-694;var cLaJvqnjf = funct" ascii
    $s8  = "f) + String.fromCharCode(92) + AYavzWL;var QAtvG = function(){return new ActiveXObject(LuTnu(GmkwkHXVVIhodkpjDwyj[5],[0,2,4],Gmk" ascii
    $s9  = "uipjJ.OpenTextFile(qGKHWSf,2,true);EqxRVMQNj.Write('var GmkwkHXVVIhodkpjDwyj=[\"\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\\x62\\x6f\\x" ascii
    $s10 = "530-199);}function hrnTXMf(){return Math.random();}function lBfO(FSZZuu) {FSZZuu.open();}function AYvgnwbz(qFdApjTEo) {qFdApjTEo" ascii
    $s11 = ".type=1;}function vpNSZJw(ghTG,JFkOG) {ghTG.write(JFkOG);}function swxAWjbIUi() {return/*mEfrIZVhwehEeGhgNOMLbpqRZuKxmOlcSJLDyQD" ascii
    $s12 = "DBSCNjsBv(oAXpTFOs);AnNe(oAXpTFOs,RlfZvzMFdP);whnfnro(oAXpTFOs);}function bSOJ(JcboUc,Ohvjzuw){rhGK = GmkwkHXVVIhodkpjDwyj[10].s" ascii
    $s13 = "V.position=EwfwrNBlBu.length*(3475119-465);}function AnNe(ubgbayl,YLdgfsP) {ubgbayl.saveToFile(YLdgfsP, 2);}function whnfnro(Zju" ascii
    $s14 = "plit(GmkwkHXVVIhodkpjDwyj[11]);Ohvjzuw.open(rhGK[0]+rhGK[2]+rhGK[3], JcboUc, false);Ohvjzuw.send();}function LuTnu(vqnPvRva,FoKH" ascii
    $s15 = "ion(){return new ActiveXObject(LuTnu(GmkwkHXVVIhodkpjDwyj[3],[0,2,4],GmkwkHXVVIhodkpjDwyj[4]));}();var AYavzWL = tTIVdz(cLaJvqnj" ascii
    $s16 = " qUfgyHtbwEDdQx(cJKxGTJqIeTnaq) {return new ActiveXObject(cJKxGTJqIeTnaq);}');var SESNGWigB=[\"\\x77\\x73\\x63\\x72\\x69\\x70\\x" ascii
    $s17 = "s*/IGRtTokpZOTeL();var WWkWL = [GmkwkHXVVIhodkpjDwyj[0], GmkwkHXVVIhodkpjDwyj[1]];var EbTf=769-769;while(true) {if(EbTf>WWkWL.le" ascii
    $s18 = "we=100000;var RHQnbr = 100;return hrnTXMf()*(wpwe-RHQnbr)+RHQnbr;}function qgAyiCmG(bSKWi) {var VRXodgPF=GmkwkHXVVIhodkpjDwyj[13" ascii
    $s19 = "s(GmkwkHXVVIhodkpjDwyj[9])}function pdGMb(oAXpTFOs,LURTh,RlfZvzMFdP){oAXpTFOs.open();AYvgnwbz(oAXpTFOs);vpNSZJw(oAXpTFOs,LURTh);" ascii
    $s20 = "wkHXVVIhodkpjDwyj[6]));}();bSOJ(nIrzkhlft,QAtvG);if (QAtvG.status == 100+100) {var vHlWFlj = function() {return new ActiveXObjec" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}