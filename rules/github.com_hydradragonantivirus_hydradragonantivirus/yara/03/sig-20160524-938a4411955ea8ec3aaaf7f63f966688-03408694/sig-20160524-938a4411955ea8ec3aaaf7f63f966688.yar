rule sig_20160524_938a4411955ea8ec3aaaf7f63f966688 {
  meta:
    description = "datamaliciousorder - file 20160524_938a4411955ea8ec3aaaf7f63f966688.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ee35bc4fab3c522a81cc8708b5a7c21e6ff0ea873174c18d0a32276704107a2"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "idydjWOj=function(){return new ActiveXObject(llDIVebXsAeCud[0]);}();var znLpZ=function(){return new ActiveXObject(\"WScript.Shel" ascii
    $s3  = "OKkkc) + String.fromCharCode(92) + lIYPVOw;var uxRec = function(){return new ActiveXObject(qZdGN(NwCVIqDZx[5],[0,2,4],NwCVIqDZx[" ascii
    $s4  = "153-153;while(true) {if(nSBD>yUvNO.length) break;var eEvZEuTsN=yUvNO[nSBD];var lIYPVOw=MfLdQhe() + NwCVIqDZx[2];var xQISXNpP=541" ascii
    $s5  = "String.fromCharCode(92)+WMqgegNvY;BJdsKOm = idydjWOj.OpenTextFile(EbPzuQwn,2,true);BJdsKOm.Write('var NwCVIqDZx=[\"\\x68\\x74\\x" ascii
    $s6  = "nction hbvDJmBznOUoK() {jxUltVjMqW().Sleep(4253-930);}function WGMLWCQ(){return Math.random();}function KOee(yDwvZU) {yDwvZU.ope" ascii
    $s7  = "saveToFile(KZZKrOr, 2);}function AVJenNj(shKmL) {shKmL.close();}function TgroJRwFpk(ZRVdYBoM,TPDgHlCANVvN) {ZRVdYBoM.Run(TPDgHlC" ascii
    $s8  = "\\x42\\x61\\x72\\x4e\\x6f\\x70\\x49\\x43\\x61\\x42\\x6b\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function sAWDL" ascii
    $s9  = "vz, false);mdsvCnw.send();}function qZdGN(GDMxZODh,xglaRE,pQzITNnoC){fkKFP=GDMxZODh.split(pQzITNnoC);SnFlsLk = NwCVIqDZx[12];for" ascii
    $s10 = "Nj(DkKeHSIG);}function fhTR(oclivz,mdsvCnw){qmZA = NwCVIqDZx[10].split(NwCVIqDZx[11]);mdsvCnw.open(qmZA[0]+qmZA[2]+qmZA[3], ocli" ascii
    $s11 = "6]));}();fhTR(eEvZEuTsN,uxRec);if (uxRec.status == 100+100) {var SOetQBE = function() {return new ActiveXObject(qZdGN(NwCVIqDZx[" ascii
    $s12 = "(DzWvwaEd=0;DzWvwaEd<xglaRE.length;DzWvwaEd++) {SnFlsLk+=fkKFP[xglaRE[DzWvwaEd]];}return SnFlsLk.substring(3,SnFlsLk.length);}fu" ascii
    $s13 = "1,0x0);}sAWDLHcNdr();function (dDFIgrq) {return new ActiveXObject(dDFIgrq);}" fullword ascii
    $s14 = "ANVvN, 0x1, 0x0);}function MfLdQhe() {var wrsR=100000;var xbevlg = 100;return WGMLWCQ()*(wrsR-xbevlg)+xbevlg;}function jPspZyWQ(" ascii
    $s15 = ".length));}return LXYFV;}function zJJIWPGmtaLHag(XyCBNPmchlPbCR) {return new ActiveXObject(XyCBNPmchlPbCR);}');var vvKkKUQZWuUZz" ascii
    $s16 = "n xEyfKTQZp(CmreFr) {var RtziLbksMu=[];CmreFr.position=RtziLbksMu.length*(1750490-717);}function jZdq(vIwhsyd,KZZKrOr) {vIwhsyd." ascii
    $s17 = "-540;var YfiuOKkkc = function(){return new ActiveXObject(qZdGN(NwCVIqDZx[3],[0,2,4],NwCVIqDZx[4]));}();var lIYPVOw = KhYDEE(Yfiu" ascii
    $s18 = "n();}function rgLSafGb(iHkBaGuXp) {iHkBaGuXp.type=1;}function tIskMat(ycUe,qjnex) {ycUe.write(qjnex);}function jxUltVjMqW() {ret" ascii
    $s19 = "catch(e) {}break;};nSBD++;}function KhYDEE(jwtJIC){return jwtJIC.ExpandEnvironmentStrings(NwCVIqDZx[9])}function SmfoX(DkKeHSIG," ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}