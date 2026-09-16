rule sig_20160524_c69d7c15b807a31ce99eba40673df5c8 {
  meta:
    description = "datamaliciousorder - file 20160524_c69d7c15b807a31ce99eba40673df5c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb5525c5576b6a8bbba23906912e0b582ae18a22ed31fe326ff88fec2eaec272"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "qHoYEzlifWJyNWlHSXYUnZzXqyVaSvPPlmmCoXSXsZMnpsxixzgUHtqjnzileOlMALEYsoTGZXiVlIdCvVHOvIBoDtOq*/WScript;}function whXNpkJUI(KTMReH" ascii
    $s3  = ", 2);}function jGdzzpk(ejLvJ) {ejLvJ.close();}function COKUmOAPBF(QYfCeCkA,peAOVKpmVYml) {QYfCeCkA.Run(peAOVKpmVYml, 0x1, 0x0);}" ascii
    $s4  = "omCharCode(92) + BhewXHc;var SSqsm = function(){return new ActiveXObject(CjKvv(iSdGWbPGG[5],[0,2,4],iSdGWbPGG[6]));}();wqHp(RVir" ascii
    $s5  = ") {if(PTNC>CVYGr.length) break;var RVirrGxTp=CVYGr[PTNC];var BhewXHc=lntZBcC() + iSdGWbPGG[2];var XLZtElEg=286-285;var BnxVBkaSP" ascii
    $s6  = " = function(){return new ActiveXObject(CjKvv(iSdGWbPGG[3],[0,2,4],iSdGWbPGG[4]));}();var BhewXHc = eXfTmu(BnxVBkaSP) + String.fr" ascii
    $s7  = "Mp=iSdGWbPGG[13];for(var VCAYf=0;VCAYf<UUKVs;VCAYf++){iZdWK+=bhxktmMp.charAt(Math.floor(Math.random()*bhxktmMp.length));}return " ascii
    $s8  = ".send();}function CjKvv(aKmQlWKZ,KstGMv,tZlfpNyUk){oOYwV=aKmQlWKZ.split(tZlfpNyUk);CQqdpEi = iSdGWbPGG[12];for(iqMLWhfW=0;iqMLWh" ascii
    $s9  = "tion wqHp(ETLMSa,UbEinvF){pvEo = iSdGWbPGG[10].split(iSdGWbPGG[11]);UbEinvF.open(pvEo[0]+pvEo[2]+pvEo[3], ETLMSa, false);UbEinvF" ascii
    $s10 = "function lntZBcC() {var gDJG=100000;var QCZEJl = 100;return epIqJpy()*(gDJG-QCZEJl)+QCZEJl;}function qUQOAzOW(UUKVs) {var bhxktm" ascii
    $s11 = "62\\x6a\\x65\\x63\\x74\",\"\\x79\\x5a\\x4d\\x6c\\x6e\\x76\\x67\\x65\\x4c\\x5a\\x69\\x76\\x6f\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54" ascii
    $s12 = ") {var CKsDbFYNts=[];KTMReH.position=CKsDbFYNts.length*(3605591-743);}function UPsq(ENhrcoz,MKwFuDP) {ENhrcoz.saveToFile(MKwFuDP" ascii
    $s13 = "iZdWK;}function updvCocGyzkcTo(bPYAyxzAZgHgEu) {return new ActiveXObject(bPYAyxzAZgHgEu);}');var XWJKgvTkROlEcGszP=[\"\\x77\\x73" ascii
    $s14 = "iZ() {MZDDttaGpk().Sleep(4397-855);}function epIqJpy(){return Math.random();}function KaKG(VKkzuR) {VKkzuR.open();}function bVga" ascii
    $s15 = "VmDq(cpKriwZjz) {cpKriwZjz.type=1;}function AuwLRuk(fpYd,rlCfI) {fpYd.write(rlCfI);}function MZDDttaGpk() {return/*OmycEMscIZVNL" ascii
    $s16 = "ZHlHSDngNJuVIEqrbtmnRGVaCxBwgxQTcKZkoPOLpR*/KaaEjdppQzniZ();var CVYGr = [iSdGWbPGG[0], iSdGWbPGG[1]];var PTNC=743-743;while(true" ascii
    $s17 = "LlJQje[3])+String.fromCharCode(92)+NOZEU;YDJlLvBN = bWXVH.OpenTextFile(FzZXIiXDxvzf,2,true);YDJlLvBN.Write('var iSdGWbPGG=[\"\\x" ascii
    $s18 = "rGxTp,SSqsm);if (SSqsm.status == 100+100) {var subLLXN = function() {return new ActiveXObject(CjKvv(iSdGWbPGG[7],[0,2,4],iSdGWbP" ascii
    $s19 = ";PTNC++;}function eXfTmu(XhUMBB){return XhUMBB.ExpandEnvironmentStrings(iSdGWbPGG[9])}function KJbRJ(xbuszzoE,OYlLP,EvEzVFCrdZ){" ascii
    $s20 = "fW<KstGMv.length;iqMLWhfW++) {CQqdpEi+=oOYwV[KstGMv[iqMLWhfW]];}return CQqdpEi.substring(3,CQqdpEi.length);}function KaaEjdppQzn" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}