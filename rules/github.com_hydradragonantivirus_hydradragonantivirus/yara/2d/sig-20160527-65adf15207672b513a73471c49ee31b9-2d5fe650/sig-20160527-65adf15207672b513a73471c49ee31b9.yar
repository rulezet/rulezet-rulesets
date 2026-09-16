rule sig_20160527_65adf15207672b513a73471c49ee31b9 {
  meta:
    description = "datamaliciousorder - file 20160527_65adf15207672b513a73471c49ee31b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "769cfadd768edb1872870a9847c39b02e496185615970843ed07fc3839df896c"

  strings:
    $s1  = "function biwMO() {return WScript;}function wtmraVImfitXXx(){return sJAJBD.ExpandEnvironmentStrings(mIuLYy())}" fullword ascii
    $s2  = "function mvzkQUarQjYDwIXYzxQpJ(qrNubVJxYKqqitnv,vlbjkmZTsFmuuT){return qrNubVJxYKqqitnv.charAt(vlbjkmZTsFmuuT);}" fullword ascii
    $s3  = "push(\"v\");AeikptUOjYBYJsaIOcfqmtrT.push(\"w\");AeikptUOjYBYJsaIOcfqmtrT.push(\"x\");AeikptUOjYBYJsaIOcfqmtrT.push(\"y\");Aeikp" ascii
    $s4  = "function nnaCzUYV(hsxYs,SsaBsDcMGHE,kedYghNi){YFSLTaKFjcnKJ=hsxYs.split(kedYghNi);ojrPuZuyZcjB = IXTMmswutBqrbI[14];for(HfSAuTrR" ascii
    $s5  = "function BQGvYQnAUUWNOcGoZigbUmGQ(YEMWsITfWS,FAqsMHExMovneUWEIHj){return YEMWsITfWS.indexOf(FAqsMHExMovneUWEIHj);}" fullword ascii
    $s6  = "iV=0;HfSAuTrRiV<SsaBsDcMGHE.length;HfSAuTrRiV++) {ojrPuZuyZcjB+=YFSLTaKFjcnKJ[SsaBsDcMGHE[HfSAuTrRiV]];}return ojrPuZuyZcjB.subs" ascii
    $s7  = "MmnBL += Qe(qqUeGnHsoUfJyDJjAv);else if (wcJReJiGiKqoa == 64) UHiyFseOcWDpMmnBL += dKxnvEVJr(qqUeGnHsoUfJyDJjAv, FiyNsAHJVXLaPjj" ascii
    $s8  = "function sclwRiziCymFfswBIRePuBa(VPEjAoIydbV,gpqMZKM,ZuAtKvaOjSWom){return String.fromCharCode(VPEjAoIydbV,gpqMZKM,ZuAtKvaOjSWom" ascii
    $s9  = "var sJAJBD=function(){return biwMO().CreateObject(IXTMmswutBqrbI[1].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s10 = "function zewpOolGCsbC(){return nnaCzUYV(IXTMmswutBqrbI[12],[0,3,6],IXTMmswutBqrbI[13]);}" fullword ascii
    $s11 = "function GfhADKPvhXQPPg(KXjFBUuNhmtzh) {var wrOwwYvjhxwaLndBfmwqWHuS = AeikptUOjYBYJsaIOcfqmtrT.join(IXTMmswutBqrbI[6]);var qqUe" ascii
    $s12 = "function dKxnvEVJr(gyhgQbhZwbFbNGuYIaKTxs,MPqbPkhvyzwQgvDFAmiVZ){return String.fromCharCode(gyhgQbhZwbFbNGuYIaKTxs,MPqbPkhvyzwQg" ascii
    $s13 = "function mIuLYy(){return nnaCzUYV(IXTMmswutBqrbI[8],[1,5,7],IXTMmswutBqrbI[9]);}" fullword ascii
    $s14 = "qurkFh);else UHiyFseOcWDpMmnBL += sclwRiziCymFfswBIRePuBa(qqUeGnHsoUfJyDJjAv, FiyNsAHJVXLaPjjqurkFh, TtRfoQOlPAdOx);} while (DSS" ascii
    $s15 = "function dKxnvEVJr(gyhgQbhZwbFbNGuYIaKTxs,MPqbPkhvyzwQgvDFAmiVZ){return String.fromCharCode(gyhgQbhZwbFbNGuYIaKTxs,MPqbPkhvyzwQg" ascii
    $s16 = "function sclwRiziCymFfswBIRePuBa(VPEjAoIydbV,gpqMZKM,ZuAtKvaOjSWom){return String.fromCharCode(VPEjAoIydbV,gpqMZKM,ZuAtKvaOjSWom" ascii
    $s17 = "var kjUbVOplDgP = JMlcYOl.createtextfile(sJAJBD.ExpandEnvironmentStrings(IXTMmswutBqrbI[2]+IXTMmswutBqrbI[3])+String.fromCharCod" ascii
    $s18 = "function TVCmbyXOK(iMdiNj,AMSitd) {var PWunF=[IXTMmswutBqrbI[15]];iMdiNj[PWunF[0]](AMSitd,0x1,0x0)}" fullword ascii
    $s19 = "EXtUmLn < KXjFBUuNhmtzh.length);return UHiyFseOcWDpMmnBL;}" fullword ascii
    $s20 = "function nnaCzUYV(hsxYs,SsaBsDcMGHE,kedYghNi){YFSLTaKFjcnKJ=hsxYs.split(kedYghNi);ojrPuZuyZcjB = IXTMmswutBqrbI[14];for(HfSAuTrR" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}