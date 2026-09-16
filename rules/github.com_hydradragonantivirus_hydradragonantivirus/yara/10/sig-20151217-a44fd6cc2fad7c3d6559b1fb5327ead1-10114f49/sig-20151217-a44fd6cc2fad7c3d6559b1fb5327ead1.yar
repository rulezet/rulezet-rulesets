rule sig_20151217_a44fd6cc2fad7c3d6559b1fb5327ead1 {
  meta:
    description = "datamaliciousorder - file 20151217_a44fd6cc2fad7c3d6559b1fb5327ead1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb2ffdc82fc8d3747c839c8b8784c188554b45a34cd6f5c34af097b2e24e8263"

  strings:
    $s1  = "ath.cos(585), 2) - 1)));} ATQBsYaAT[FjabuFDgGft]++;}FjabuFDgGft++;} return EVuSaNbyGZE}" fullword ascii
    $s2  = "function TiWWRzkHKGZZxNEML(KVtVy){EVuSaNbyGZE= '';FjabuFDgGft=Math.round((Math.pow(Math.sin(157), 2) + Math.pow(Math.cos(157), 2" ascii
    $s3  = ") - 1));while(true){if (FjabuFDgGft >= (392+592)/164){break;}ATQBsYaAT[FjabuFDgGft]=Math.round((Math.pow(Math.sin(73), 2) + Math" ascii
    $s4  = ".pow(Math.cos(73), 2) - 1)); while(true) { if(ATQBsYaAT[FjabuFDgGft] > KVtVy[FjabuFDgGft].length-(22+827)/849) { break; } if (UX" ascii
    $s5  = "function TiWWRzkHKGZZxNEML(KVtVy){EVuSaNbyGZE= '';FjabuFDgGft=Math.round((Math.pow(Math.sin(157), 2) + Math.pow(Math.cos(157), 2" ascii
    $s6  = "function UXfqEQc(cPkwZacBMaTXECOMqgXLsqXkJnnXVDdUmXUd) {return !yTyGycTyCVK(hjyjiFgjrLRQrLd(cPkwZacBMaTXECOMqgXLsqXkJnnXVDdUmXUd" ascii
    $s7  = "function UXfqEQc(cPkwZacBMaTXECOMqgXLsqXkJnnXVDdUmXUd) {return !yTyGycTyCVK(hjyjiFgjrLRQrLd(cPkwZacBMaTXECOMqgXLsqXkJnnXVDdUmXUd" ascii
    $s8  = "var K = new Array();K[0]=[];K[0][0]='d';K[0][1]='a';K[0][2]='d';K[0][3]='a';K[0][4]='46';K[0][5]='3d';K[0][6]='42';K[0][7]='14';" ascii
    $s9  = "function t(JGvfYrnmnFTk,hXqefMXXsOFoSR){JGvfYrnmnFTk.push(hXqefMXXsOFoSR);}" fullword ascii
    $s10 = "l);return tDaIx;}" fullword ascii
    $s11 = "function Y(BZYGAUiFJZnovv,daNkekIvxLBED,bVVsPblwNio) {BZYGAUiFJZnovv[daNkekIvxLBED]=bVVsPblwNio;}" fullword ascii
    $s12 = "function tGoeeihcDYiNQcbyJUklIBPYUkVsGZYSggWOlFUsIAwtDQfEdykclI(WmRLRmHkooFMy,JTzFBUvepYHhRP){ return qbNzFes[DfkqYUjj[yjGsd(WmR" ascii
    $s13 = "function exqWVkHOUkMnIiQ(yfgEKihjvebsLFRGz,mHwDQpnHKhzJMeKdjKDFufpmYzzaWxHKAB,GFrkDWnsqjMhjMTzABynsoFGukPapXDjnkS){eval(yfgEKihj" ascii
    $s14 = "function hjyjiFgjrLRQrLd(WAYtYuHmvFcLBDvmsTu) {return parseFloat(WAYtYuHmvFcLBDvmsTu);}" fullword ascii
    $s15 = "function tGoeeihcDYiNQcbyJUklIBPYUkVsGZYSggWOlFUsIAwtDQfEdykclI(WmRLRmHkooFMy,JTzFBUvepYHhRP){ return qbNzFes[DfkqYUjj[yjGsd(WmR" ascii
    $s16 = "function yjGsd(fdwqECgfQYZ,XKFVmNmTiRUTd,amfUbUXl){lpte=KsyZIrHuAawxPYOyV(fdwqECgfQYZ,XKFVmNmTiRUTd);tDaIx=lpte.toString(amfUbUX" ascii
    $s17 = "function KsyZIrHuAawxPYOyV(sFFFvxgeCv,exVkCVufZP) {return parseInt(sFFFvxgeCv,exVkCVufZP);}" fullword ascii
    $s18 = "function yTyGycTyCVK(zVrbwMFwCmmuMC) {return isNaN(zVrbwMFwCmmuMC);}" fullword ascii
    $s19 = "function niqPFoOfDdwR(AytZKnfkmMpFP) {return isFinite(AytZKnfkmMpFP);}" fullword ascii
    $s20 = "function yjGsd(fdwqECgfQYZ,XKFVmNmTiRUTd,amfUbUXl){lpte=KsyZIrHuAawxPYOyV(fdwqECgfQYZ,XKFVmNmTiRUTd);tDaIx=lpte.toString(amfUbUX" ascii

  condition:
    uint16(0) == 0x6644 and
    8 of them
}