rule sig_20160524_ab4d75ba4928e21840d14a1298ddea51 {
  meta:
    description = "datamaliciousorder - file 20160524_ab4d75ba4928e21840d14a1298ddea51.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7d0e74d63fca3b4a3b6b86b8c48b5afc1399b1c2f26a4c2ca0665d5596ad532"

  strings:
    $x1  = "'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" ascii
    $s2  = "Cjp.Run(KGAugOEbfqTp, 0x1, 0x0);}function pxQYPkg() {var vFvN=100000;var uHHxnu = 100;return xmZvPfD()*(vFvN-uHHxnu)+uHHxnu;}fun" ascii
    $s3  = " SkuMGAtwxziqU=function(){return new ActiveXObject(GSWbOXvmPGrw[0]);}();var kOxllnX=function(){return new ActiveXObject(\"WScrip" ascii
    $s4  = "Script;}function WvBtuwQkl(CQqyas) {var INAPMjnZzr=[];CQqyas.position=INAPMjnZzr.length*(2410857-721);}function anvq(XxwKQVd,ERz" ascii
    $s5  = "yi) {zDRAyi.open();}function hCSBCEUB(bmpybDnlA) {bmpybDnlA.type=1;}function kBfYkpa(tjql,jlOGs) {tjql.write(jlOGs);}function Re" ascii
    $s6  = "cyU=835-835;while(true) {if(ccyU>UEcFn.length) break;var OpolPrUPD=UEcFn[ccyU];var VcOCgYZ=pxQYPkg() + PTPHwMtDYF[2];var KCtOBpy" ascii
    $s7  = "sK(YXZazGhGe) + String.fromCharCode(92) + VcOCgYZ;var ewMdF = function(){return new ActiveXObject(Nkyts(PTPHwMtDYF[5],[0,2,4],PT" ascii
    $s8  = "GUz.length);}function YAOvNTfVeOQHb() {ResPcxzFXm().Sleep(3626-891);}function xmZvPfD(){return Math.random();}function kuht(zDRA" ascii
    $s9  = ")+String.fromCharCode(92)+yUcWXvJEIPg;UbhdtpZISGDihw = SkuMGAtwxziqU.OpenTextFile(Lritdi,2,true);UbhdtpZISGDihw.Write('var PTPHw" ascii
    $s10 = "+yOrv[3], YjPInn, false);RbGOcNH.send();}function Nkyts(UuHCfxcp,utUdUu,cRijSerZh){QBjVF=UuHCfxcp.split(cRijSerZh);imFLGUz = PTP" ascii
    $s11 = "a=707-706;var YXZazGhGe = function(){return new ActiveXObject(Nkyts(PTPHwMtDYF[3],[0,2,4],PTPHwMtDYF[4]));}();var VcOCgYZ = HnXe" ascii
    $s12 = "Pfrr();function (TITCFoJWdjaa) {return new ActiveXObject(TITCFoJWdjaa);}" fullword ascii
    $s13 = "HwMtDYF[12];for(OYBosibe=0;OYBosibe<utUdUu.length;OYBosibe++) {imFLGUz+=QBjVF[utUdUu[OYBosibe]];}return imFLGUz.substring(3,imFL" ascii
    $s14 = "GLauJ);yMGTJLs(WJjuYecN);}function HrfK(YjPInn,RbGOcNH){yOrv = PTPHwMtDYF[10].split(PTPHwMtDYF[11]);RbGOcNH.open(yOrv[0]+yOrv[2]" ascii
    $s15 = "nDKB) {XxwKQVd.saveToFile(ERznDKB, 2);}function yMGTJLs(TtDfs) {TtDfs.close();}function zUEIAObIuR(gIHhfCjp,KGAugOEbfqTp) {gIHhf" ascii
    $s16 = "andom()*BgzhLhsd.length));}return vieQR;}function KdgKHbXRhdGxJq(tskrVVknyXGHNQ) {return new ActiveXObject(tskrVVknyXGHNQ);}');v" ascii
    $s17 = "x45\\x5a\\x70\\x72\\x4b\\x72\\x57\\x61\\x5a\\x52\\x7a\",\"\\x2e\\x6a\\x73\",\"\\x25\\x54\\x45\\x4d\\x50\\x25\"];function qPfrr()" ascii
    $s18 = "PHwMtDYF[6]));}();HrfK(OpolPrUPD,ewMdF);if (ewMdF.status == 100+100) {var XrkxTaO = function() {return new ActiveXObject(Nkyts(P" ascii
    $s19 = "VcOCgYZ);} catch(e) {}break;};ccyU++;}function HnXesK(mnhEjt){return mnhEjt.ExpandEnvironmentStrings(PTPHwMtDYF[9])}function SEJ" ascii

  condition:
    uint16(0) == 0x4127 and
    1 of ($x*) and 4 of them
}