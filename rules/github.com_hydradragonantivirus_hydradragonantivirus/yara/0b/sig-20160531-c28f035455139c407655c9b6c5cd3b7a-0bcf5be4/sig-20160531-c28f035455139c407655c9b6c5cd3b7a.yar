rule sig_20160531_c28f035455139c407655c9b6c5cd3b7a {
  meta:
    description = "datamaliciousorder - file 20160531_c28f035455139c407655c9b6c5cd3b7a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4853af9e1e1cf410987a8de21bf48997f1550a25741481a9ab537a756064bf0"

  strings:
    $s1  = "var QkShwkUIk=function(){return WScript.CreateObject(gfluxydHriuRkxUvS[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WjSoj(EnUEAnjcqdhhoGKuCKUNNHzZ,LYBMgLnokCNMTyBYtksWDB){return EnUEAnjcqdhhoGKuCKUNNHzZ.charAt(LYBMgLnokCNMTyBYtksWDB);}" ascii
    $s3  = "function nHvhJu(SrQoEHpkqAHeE) {var XrDLuDHyJhS = bmVnUDBgQuOzj.join(gfluxydHriuRkxUvS[7]);var IZQYhU, aekxV, dqZmbatYyKcW, Cwem" ascii
    $s4  = "function xjPHWctUPaplVQ(aFAfhOjNp,OCDCf) {var rGplwt=[gfluxydHriuRkxUvS[15]];aFAfhOjNp[rGplwt[0]]" fullword ascii
    $s5  = "hU);else if (AMeGaHDMlxPMf == 64) RYIEtOpasNRBObucWzbT += nwVqeEiVQtkHstsb(IZQYhU, aekxV);else RYIEtOpasNRBObucWzbT += jSZnV(IZQ" ascii
    $s6  = "function jm(DApkMErccyliBtWqjghwRzG){return String.fromCharCode(DApkMErccyliBtWqjghwRzG);}" fullword ascii
    $s7  = "function jSZnV(NpoqQHNKDsPcngOO,xubtNrheZLxCwrL,bUQSm){return String.fromCharCode(NpoqQHNKDsPcngOO,xubtNrheZLxCwrL,bUQSm);}" fullword ascii
    $s8  = "function ubwbgPCpvoHHeH(){return wWwuxG(gfluxydHriuRkxUvS[9],[1,5,7],gfluxydHriuRkxUvS[10]);}" fullword ascii
    $s9  = "function nwVqeEiVQtkHstsb(gCFpLF,RYDsvjXjXGdvAjcV){return String.fromCharCode(gCFpLF,RYDsvjXjXGdvAjcV);}" fullword ascii
    $s10 = "function jlPhAtItKtS(){return wWwuxG(gfluxydHriuRkxUvS[13],[0,3,6],gfluxydHriuRkxUvS[14]);}" fullword ascii
    $s11 = "YhU, aekxV, dqZmbatYyKcW);} while (glWOt < SrQoEHpkqAHeE.length);return RYIEtOpasNRBObucWzbT;}" fullword ascii
    $s12 = "(OCDCf,0x1,0x0)}function MhLwBr(GpRHANoeAwq,OyAcw,FwxLWd){var omkPzISXrATMm=GpRHANoeAwq.createtextfile(OyAcw,true);omkPzISXrATMm" ascii
    $s13 = "var llfxPRmhTfLV=function(){return new ActiveXObject(gfluxydHriuRkxUvS[1]);}();" fullword ascii
    $s14 = "(OCDCf,0x1,0x0)}function MhLwBr(GpRHANoeAwq,OyAcw,FwxLWd){var omkPzISXrATMm=GpRHANoeAwq.createtextfile(OyAcw,true);omkPzISXrATMm" ascii
    $s15 = "function eSHttOD(){return wWwuxG(gfluxydHriuRkxUvS[11],[2,4,8,10],gfluxydHriuRkxUvS[12]);}" fullword ascii
    $s16 = "PBbcId=0;ubSdlPBbcId<MVpVySGnpBIto.length;ubSdlPBbcId++) {QQXbT+=quRTBju[MVpVySGnpBIto[ubSdlPBbcId]];}return QQXbT.substring(3,Q" ascii
    $s17 = "function ZJBVJqdqeUxYW(){return QkShwkUIk.ExpandEnvironmentStrings(ubwbgPCpvoHHeH())}" fullword ascii
    $s18 = "function XQbQeimJfuwqdACadermiD(xHHFPlgKgCctcgIaetKW,DLdWydWoGJtUzOaEHVe){return xHHFPlgKgCctcgIaetKW.indexOf(DLdWydWoGJtUzOaEHV" ascii
    $s19 = "function wWwuxG(DGfTkUB,MVpVySGnpBIto,CAKNBzFFiipjp){quRTBju=DGfTkUB.split(CAKNBzFFiipjp);QQXbT = gfluxydHriuRkxUvS[0];for(ubSdl" ascii
    $s20 = "function XQbQeimJfuwqdACadermiD(xHHFPlgKgCctcgIaetKW,DLdWydWoGJtUzOaEHVe){return xHHFPlgKgCctcgIaetKW.indexOf(DLdWydWoGJtUzOaEHV" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}