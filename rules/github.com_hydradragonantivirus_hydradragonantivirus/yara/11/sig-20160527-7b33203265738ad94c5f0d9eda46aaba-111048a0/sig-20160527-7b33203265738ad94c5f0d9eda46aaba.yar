rule sig_20160527_7b33203265738ad94c5f0d9eda46aaba {
  meta:
    description = "datamaliciousorder - file 20160527_7b33203265738ad94c5f0d9eda46aaba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05be97249536629ad79d22f10a67b2e0ff6986878078bdb2d0632553f15e320b"

  strings:
    $s1  = "function LBCKCVcKSRVmar() {return WScript;}function tDAFRaFocDbhpy(){return lxXao.ExpandEnvironmentStrings(xJfNN())}" fullword ascii
    $s2  = "function iWhzMOPAaghOI(pyauHXSSJGWGmANnHUXA,BZbeORcEAKMaKj){return pyauHXSSJGWGmANnHUXA.charAt(BZbeORcEAKMaKj);}" fullword ascii
    $s3  = "function MvIkMQN(ncTqxuPkqo,OojXe){return String.fromCharCode(ncTqxuPkqo,OojXe);}" fullword ascii
    $s4  = "var siZDm = SnhYbigkOcSb.createtextfile(lxXao.ExpandEnvironmentStrings(iiPKPDBpBiJO[2]+iiPKPDBpBiJO[3])+String.fromCharCode(92)+" ascii
    $s5  = "function LR(lrLKVNKExhYYOlb){return String.fromCharCode(lrLKVNKExhYYOlb);}" fullword ascii
    $s6  = "var SnhYbigkOcSb=function(){return new ActiveXObject(iiPKPDBpBiJO[0]);}();" fullword ascii
    $s7  = "function mFsNSeioQzUg(){return RSujAacpUwQVvI(iiPKPDBpBiJO[10],[2,4,8,10],iiPKPDBpBiJO[11]);}" fullword ascii
    $s8  = "];for(RCJPEKsv=0;RCJPEKsv<ldTTzAvgB.length;RCJPEKsv++) {uhyTrdYWhRTNi+=JNjJCnHa[ldTTzAvgB[RCJPEKsv]];}return uhyTrdYWhRTNi.subst" ascii
    $s9  = "var lxXao=function(){return LBCKCVcKSRVmar().CreateObject(iiPKPDBpBiJO[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function WQJdB(FCWOMGmrNSGiTBfGMDa,jisSWmORwOOjYfwK){return FCWOMGmrNSGiTBfGMDa.indexOf(jisSWmORwOOjYfwK);}" fullword ascii
    $s11 = "function UuylzlYK(NMPXQaRpQhgmEKW,FmsGdyeamwHoVgrEjBZgSsS,XEwZeHrEgmbhWY){return String.fromCharCode(NMPXQaRpQhgmEKW,FmsGdyeamwH" ascii
    $s12 = "function UuylzlYK(NMPXQaRpQhgmEKW,FmsGdyeamwHoVgrEjBZgSsS,XEwZeHrEgmbhWY){return String.fromCharCode(NMPXQaRpQhgmEKW,FmsGdyeamwH" ascii
    $s13 = " 0xff;LZnmParfxZzvrr = NWCiLRbmYKtEtaBUnxlA & 0xff;if (STMsazKPKenwUqlH == 64) jZAESx += LR(yluMuSCuOZojMdn);else if (EdGGudgtwe" ascii
    $s14 = "iiPKPDBpBiJO[4],true);" fullword ascii
    $s15 = "function TOorhHn(CjVNBuoOSLmnt) {var OzcEBvw = aprPyCPb.join(iiPKPDBpBiJO[6]);var yluMuSCuOZojMdn, nDEjpbkMoaFoiW, LZnmParfxZzvr" ascii
    $s16 = "ring(3,uhyTrdYWhRTNi.length);}" fullword ascii
    $s17 = "function mpKsZ(){return RSujAacpUwQVvI(iiPKPDBpBiJO[12],[0,3,6],iiPKPDBpBiJO[13]);}" fullword ascii
    $s18 = " == 64) jZAESx += MvIkMQN(yluMuSCuOZojMdn, nDEjpbkMoaFoiW);else jZAESx += UuylzlYK(yluMuSCuOZojMdn, nDEjpbkMoaFoiW, LZnmParfxZzv" ascii
    $s19 = "function TOorhHn(CjVNBuoOSLmnt) {var OzcEBvw = aprPyCPb.join(iiPKPDBpBiJO[6]);var yluMuSCuOZojMdn, nDEjpbkMoaFoiW, LZnmParfxZzvr" ascii
    $s20 = "function RSujAacpUwQVvI(GFojrAVex,ldTTzAvgB,HBDLKvhNOBTW){JNjJCnHa=GFojrAVex.split(HBDLKvhNOBTW);uhyTrdYWhRTNi = iiPKPDBpBiJO[14" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}