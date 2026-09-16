rule sig_20160527_dd6b68f9b617fba1d1f5d378a11656ec {
  meta:
    description = "datamaliciousorder - file 20160527_dd6b68f9b617fba1d1f5d378a11656ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26eccabeef7590234001e78b9e732da3d22a5bf25f2427bc0074b00079333d87"

  strings:
    $s1  = "function BxcuaFNbCXqCZ() {return WScript;}function KqcjJoFLyBz(){return kRhQegiT.ExpandEnvironmentStrings(zLGdpVQQBw())}" fullword ascii
    $s2  = "function raNBZIJl(NTfTPxXfiyu,wxYmUOnVQS) {var zbJRCHQLy=[httxCm[15]];NTfTPxXfiyu[zbJRCHQLy[0]](wxYmUOnVQS,0x1,0x0)}" fullword ascii
    $s3  = "function AQjERMzggMm(pLTVXVvm,wjYJLPZlKnPRUdDKpLEh){return pLTVXVvm.charAt(wjYJLPZlKnPRUdDKpLEh);}" fullword ascii
    $s4  = "function OwqoRnLS(SzDXKKbPF,lJrcqgfAwMUm){return SzDXKKbPF.indexOf(lJrcqgfAwMUm);}" fullword ascii
    $s5  = "OfWYhYl += gxcfzveDaTjATUGCHn(yFXtZo, VCbSSUzXgMlkIKZLPuCK);else QWrOfWYhYl += LnuXNsZ(yFXtZo, VCbSSUzXgMlkIKZLPuCK, eScMBepQHGo" ascii
    $s6  = "var hrVzOUzdLDmQQc = QfuNc.createtextfile(kRhQegiT.ExpandEnvironmentStrings(httxCm[2]+httxCm[3])+String.fromCharCode(92)+httxCm[" ascii
    $s7  = "function hiDXqne(NgwmJCzNSKw,WTVqtIPk,aakshXsfp){OjJlKAqfslygd=NgwmJCzNSKw.split(aakshXsfp);pFYULvwV = httxCm[14];for(KnwkZ=0;Kn" ascii
    $s8  = "function hiDXqne(NgwmJCzNSKw,WTVqtIPk,aakshXsfp){OjJlKAqfslygd=NgwmJCzNSKw.split(aakshXsfp);pFYULvwV = httxCm[14];for(KnwkZ=0;Kn" ascii
    $s9  = "var kRhQegiT=function(){return BxcuaFNbCXqCZ().CreateObject(httxCm[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function bcpsBsaPIw(){return hiDXqne(httxCm[10],[2,4,8,10],httxCm[11]);}" fullword ascii
    $s11 = "CckaJqX);} while (zFPmw < HIbttGGJQOOJY.length);return QWrOfWYhYl;}" fullword ascii
    $s12 = "function PZVJhLVbxvipV(HIbttGGJQOOJY) {var zryftBaJtnxlJCpjQ = dbUbovkPLmQmlWN.join(httxCm[6]);var yFXtZo, VCbSSUzXgMlkIKZLPuCK," ascii
    $s13 = "CckaJqX = CXeGAycMmZpDwcwpdlzjD & 0xff;if (JJYFBFgqSxuEhJvr == 64) QWrOfWYhYl += pe(yFXtZo);else if (MLCRTFfUpVRMjQUI == 64) QWr" ascii
    $s14 = "function gxcfzveDaTjATUGCHn(CRUgEvpCGlROO,TZkEQSraRkLKYcdMHIRa){return String.fromCharCode(CRUgEvpCGlROO,TZkEQSraRkLKYcdMHIRa);}" ascii
    $s15 = "function PZVJhLVbxvipV(HIbttGGJQOOJY) {var zryftBaJtnxlJCpjQ = dbUbovkPLmQmlWN.join(httxCm[6]);var yFXtZo, VCbSSUzXgMlkIKZLPuCK," ascii
    $s16 = "var QfuNc=function(){return new ActiveXObject(httxCm[0]);}();" fullword ascii
    $s17 = "function pe(yCCUPkVwWuwEGEf){return String.fromCharCode(yCCUPkVwWuwEGEf);}" fullword ascii
    $s18 = "function LnuXNsZ(ubRIFmYTNTAgSBRhkBk,ohUqBQlkpYGbstXlPrgN,vDALjEJcMvWDydqrbKwuqjdJ){return String.fromCharCode(ubRIFmYTNTAgSBRhk" ascii
    $s19 = "function jdeACKPzlh(){return hiDXqne(httxCm[12],[0,3,6],httxCm[13]);}" fullword ascii
    $s20 = "wkZ<WTVqtIPk.length;KnwkZ++) {pFYULvwV+=OjJlKAqfslygd[WTVqtIPk[KnwkZ]];}return pFYULvwV.substring(3,pFYULvwV.length);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}