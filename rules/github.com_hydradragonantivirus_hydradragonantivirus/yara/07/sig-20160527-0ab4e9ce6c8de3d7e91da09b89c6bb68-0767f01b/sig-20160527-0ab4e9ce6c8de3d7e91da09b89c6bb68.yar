rule sig_20160527_0ab4e9ce6c8de3d7e91da09b89c6bb68 {
  meta:
    description = "datamaliciousorder - file 20160527_0ab4e9ce6c8de3d7e91da09b89c6bb68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5782f0dbd333fbbea690f22b5c9248cff945616d37267b8905d5cd8c3f2d8274"

  strings:
    $s1  = "function eGVusFFe() {return WScript;}function RaWQAmlfApQxE(){return BLCFCUUcvLB.ExpandEnvironmentStrings(nrLUy())}" fullword ascii
    $s2  = "function cgsoPUOUneZylSXeJy(ChBnZ,beqkdnGzKfxgsBUaiAIeUqrF){return ChBnZ.charAt(beqkdnGzKfxgsBUaiAIeUqrF);}" fullword ascii
    $s3  = "function CqppT(){return ZXUhOn(WSrpByoRWCIVeyOinGCVJccI[10],[2,4,8,10],WSrpByoRWCIVeyOinGCVJccI[11]);}" fullword ascii
    $s4  = "function ZXUhOn(JShtKNUgNoVvv,cXaYntfsE,EzfkmdfnCN){jUhmQXNYpcoxCJ=JShtKNUgNoVvv.split(EzfkmdfnCN);HTOJxmGTbP = WSrpByoRWCIVeyOi" ascii
    $s5  = "var ZzeyjtOWrkTy = NzRyxnmYLmXLR.createtextfile(BLCFCUUcvLB.ExpandEnvironmentStrings(WSrpByoRWCIVeyOinGCVJccI[2]+WSrpByoRWCIVeyO" ascii
    $s6  = "function ZWRwhPnJiFICvLeCOkUoR(asLZCNObdPqURkkMhOUNFQMP,aJzQOXVS){return String.fromCharCode(asLZCNObdPqURkkMhOUNFQMP,aJzQOXVS);" ascii
    $s7  = "var BLCFCUUcvLB=function(){return eGVusFFe().CreateObject(WSrpByoRWCIVeyOinGCVJccI[1].replace(new RegExp(\"u\",\"g\"),\"\"));}()" ascii
    $s8  = "function blIDRUqByKb(MxNupYdFv,UqxZrJyKQxRyQMuxHGDkBT,xRZSVKReYPIgfTJIkKYQz){return String.fromCharCode(MxNupYdFv,UqxZrJyKQxRyQM" ascii
    $s9  = "sHPO]];}return HTOJxmGTbP.substring(3,HTOJxmGTbP.length);}" fullword ascii
    $s10 = "e if (lJtsDNzFCOSGXIueVt == 64) vWWJrtWXuarOWA += ZWRwhPnJiFICvLeCOkUoR(oLensDecpy, kQiIkMhnRVkbCXbWmiNwOdg);else vWWJrtWXuarOWA" ascii
    $s11 = "function ZXUhOn(JShtKNUgNoVvv,cXaYntfsE,EzfkmdfnCN){jUhmQXNYpcoxCJ=JShtKNUgNoVvv.split(EzfkmdfnCN);HTOJxmGTbP = WSrpByoRWCIVeyOi" ascii
    $s12 = "function IsclvqyMGgh(pgMYKJCJTHXKH) {var ohjKTyLmwd = flxnXeLnldyIbxqwcFZciMT.join(WSrpByoRWCIVeyOinGCVJccI[6]);var oLensDecpy, " ascii
    $s13 = "function xl(dNcEYpxDpWrwdaifWCigDvBj){return String.fromCharCode(dNcEYpxDpWrwdaifWCigDvBj);}" fullword ascii
    $s14 = "function ctbUoLstH(BDGbZAgTFCLEtG,EbdlQREvBR) {var hYTzNCWKaU=[WSrpByoRWCIVeyOinGCVJccI[15]];BDGbZAgTFCLEtG[hYTzNCWKaU[0]](EbdlQ" ascii
    $s15 = "function ZWRwhPnJiFICvLeCOkUoR(asLZCNObdPqURkkMhOUNFQMP,aJzQOXVS){return String.fromCharCode(asLZCNObdPqURkkMhOUNFQMP,aJzQOXVS);" ascii
    $s16 = "function ctbUoLstH(BDGbZAgTFCLEtG,EbdlQREvBR) {var hYTzNCWKaU=[WSrpByoRWCIVeyOinGCVJccI[15]];BDGbZAgTFCLEtG[hYTzNCWKaU[0]](EbdlQ" ascii
    $s17 = "function tigmHiaHYWRjiA(iwIOTUj,MmplGcdZmxlWooZCkJggXD){return iwIOTUj.indexOf(MmplGcdZmxlWooZCkJggXD);}" fullword ascii
    $s18 = "function nrLUy(){return ZXUhOn(WSrpByoRWCIVeyOinGCVJccI[8],[1,5,7],WSrpByoRWCIVeyOinGCVJccI[9]);}" fullword ascii
    $s19 = "function blIDRUqByKb(MxNupYdFv,UqxZrJyKQxRyQMuxHGDkBT,xRZSVKReYPIgfTJIkKYQz){return String.fromCharCode(MxNupYdFv,UqxZrJyKQxRyQM" ascii
    $s20 = "inGCVJccI[3])+String.fromCharCode(92)+WSrpByoRWCIVeyOinGCVJccI[4],true);" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}