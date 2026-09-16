rule sig_20160524_0b1d1a8db71989726c0bd3bb72960295 {
  meta:
    description = "datamaliciousorder - file 20160524_0b1d1a8db71989726c0bd3bb72960295.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "57b23656eed57d98f8db974ce86098a624831589c473fe34df0dbeb97f51c59c"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "veXObject(bNTBYtRPmRaQbSwWJegYMyP[0]);}();var ROArLXtlJq=function(){return new ActiveXObject(\"WScript.Shell\");}();var zyYSToPE" ascii
    $s3  = "sf.close();}function KsTDiDsTIA(tLEJaqMb,UvybdkGIjvDu) {tLEJaqMb.Run(UvybdkGIjvDu, 0x1, 0x0);}function CkKUBBj() {var KGax=10000" ascii
    $s4  = "KVXqtXUokeuqTKWDGFxEiixALkTUadlRnGvXikYrYHRCtpyLGZSvuexMXw*/WScript;}function EfgeCUNHi(wtoXOk) {var STBXJtPQHw=[];wtoXOk.positi" ascii
    $s5  = "2e\\x65\\x78\\x65\\x20\"];daPqbD.Close();ROArLXtlJq.Run(RTsAwUTOSslolBvrw[0]+kpuSdff,0x1,0x0);}CjkLCVDVmeJ();function (mZjNISnmL" ascii
    $s6  = "r(var lOBFv=0;lOBFv<qhHpe;lOBFv++){ordOw+=vwfrEmub.charAt(Math.floor(Math.random()*vwfrEmub.length));}return ordOw;}function nhJ" ascii
    $s7  = "KUBBj() + SbfIVNEtMdAAQLZJEkVUBctP[2];var OozCLoQA=354-353;var yNxOslxCn = function(){return new ActiveXObject(wgSgX(SbfIVNEtMdA" ascii
    $s8  = "BjaYYEqLgSA(cnOFCcLbpLCNUa) {return new ActiveXObject(cnOFCcLbpLCNUa);}');var RTsAwUTOSslolBvrw=[\"\\x77\\x73\\x63\\x72\\x69\\x7" ascii
    $s9  = "on=STBXJtPQHw.length*(3573812-859);}function hDdB(KtOFcZh,ioFZiYX) {KtOFcZh.saveToFile(ioFZiYX, 2);}function JdmncRI(mwWsf) {mwW" ascii
    $s10 = "hDdB(HSsIJNpF,IxrrGSEebw);JdmncRI(HSsIJNpF);}function kyEC(HGCbVg,FkxdaWn){dwDN = SbfIVNEtMdAAQLZJEkVUBctP[10].split(SbfIVNEtMdA" ascii
    $s11 = " SbfIVNEtMdAAQLZJEkVUBctP[1]];var PwCX=534-534;while(true) {if(PwCX>AoDYd.length) break;var HuGMQeNLv=AoDYd[PwCX];var uPfOPRh=Ck" ascii
    $s12 = "AQLZJEkVUBctP[11]);FkxdaWn.open(dwDN[0]+dwDN[2]+dwDN[3], HGCbVg, false);FkxdaWn.send();}function wgSgX(OAPgUczP,xcUpVG,nymtpJVtm" ascii
    $s13 = "tP[9])}function rqAlm(HSsIJNpF,ZXtAJ,IxrrGSEebw){HSsIJNpF.open();gxBhuOVP(HSsIJNpF);ONBqJFv(HSsIJNpF,ZXtAJ);EfgeCUNHi(HSsIJNpF);" ascii
    $s14 = "}function ONBqJFv(YtPv,rswMn) {YtPv.write(rswMn);}function ongiZyGyum() {return/*WodqudhVSOjMGUpaEtdxdKEpVRylynOzEWhPEqGtruSWiFT" ascii
    $s15 = "HuGMQeNLv,IOGHJ);if (IOGHJ.status == 100+100) {var dxyPdDL = function() {return new ActiveXObject(wgSgX(SbfIVNEtMdAAQLZJEkVUBctP" ascii
    $s16 = "QyS+=sirbd[xcUpVG[MUlNbIag]];}return UoKbQyS.substring(3,UoKbQyS.length);}function mpYsJjKKNYRRV() {ongiZyGyum().Sleep(3503-983)" ascii
    $s17 = "wWJegYMyP[3])+String.fromCharCode(92)+zyYSToPEtypSy;daPqbD = bjBNuEa.OpenTextFile(kpuSdff,2,true);daPqbD.Write('var SbfIVNEtMdAA" ascii
    $s18 = ";}function KDDtYqS(){return Math.random();}function PUIk(QiZdBa) {QiZdBa.open();}function gxBhuOVP(HcnJmMJaa) {HcnJmMJaa.type=1;" ascii
    $s19 = "ar IOGHJ = function(){return new ActiveXObject(wgSgX(SbfIVNEtMdAAQLZJEkVUBctP[5],[0,2,4],SbfIVNEtMdAAQLZJEkVUBctP[6]));}();kyEC(" ascii
    $s20 = "0;var LGFhHU = 100;return KDDtYqS()*(KGax-LGFhHU)+LGFhHU;}function PsKpCHGh(qhHpe) {var vwfrEmub=SbfIVNEtMdAAQLZJEkVUBctP[13];fo" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}