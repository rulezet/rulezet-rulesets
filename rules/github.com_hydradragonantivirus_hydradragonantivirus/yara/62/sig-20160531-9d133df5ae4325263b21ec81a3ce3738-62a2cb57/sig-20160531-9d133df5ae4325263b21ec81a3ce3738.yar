rule sig_20160531_9d133df5ae4325263b21ec81a3ce3738 {
  meta:
    description = "datamaliciousorder - file 20160531_9d133df5ae4325263b21ec81a3ce3738.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e1f36758cbed59001ccdbc30edbf590b16bdb3d51672a95618b392da555c325"

  strings:
    $s1  = "var YnzhNXIb=function(){return WScript.CreateObject(ACTYattYOdukOP[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function JHfoCyAqJjlKEXUD(TsatbRJqhIg,lmAAQmAiAZQ){return TsatbRJqhIg.charAt(lmAAQmAiAZQ);}" fullword ascii
    $s3  = "function yjlqWTYF(HLvKx,erCBJgFlJsjk,YzSquRr){EjDJFBe=HLvKx.split(YzSquRr);rNEUg = ACTYattYOdukOP[0];for(WpdrbkxNnHGt=0;WpdrbkxN" ascii
    $s4  = "function lfnNHWiqr(yAYqWQfRGMoJHwrC,suuwD){return String.fromCharCode(yAYqWQfRGMoJHwrC,suuwD);}" fullword ascii
    $s5  = "function Fihihup(lFxEBMLfxbVRV) {var UwHif = BTvsfiheVHH.join(ACTYattYOdukOP[7]);var bBOYEYC, gwdHfSOXVOnDbVH, SSJzJTGqJtoFZpkoU" ascii
    $s6  = "function ZvhWaFfgEvBteIsUxZYhCC(mZozkXBVOVAwMtvozBabaRG,FlQhAzPQiaDzYZjoTETyM){return mZozkXBVOVAwMtvozBabaRG.indexOf(FlQhAzPQia" ascii
    $s7  = "(XTRSPoQ,0x1,0x0)}function oYKYGvZ(foLCUgY,oIJigYRFEvQcx,UqfzvOe){var jaAheKpFtbOpfM=foLCUgY.createtextfile(oIJigYRFEvQcx,true);" ascii
    $s8  = "function ZvhWaFfgEvBteIsUxZYhCC(mZozkXBVOVAwMtvozBabaRG,FlQhAzPQiaDzYZjoTETyM){return mZozkXBVOVAwMtvozBabaRG.indexOf(FlQhAzPQia" ascii
    $s9  = "nHGt<erCBJgFlJsjk.length;WpdrbkxNnHGt++) {rNEUg+=EjDJFBe[erCBJgFlJsjk[WpdrbkxNnHGt]];}return rNEUg.substring(3,rNEUg.length);}" fullword ascii
    $s10 = "C, gwdHfSOXVOnDbVH, SSJzJTGqJtoFZpkoUObY);} while (IyahsNfpHGoZHucTBYqftRs < lFxEBMLfxbVRV.length);return fEDCZYq;}" fullword ascii
    $s11 = "e if (OgHqyQCwSzQFtQtCwVfqxxj == 64) fEDCZYq += lfnNHWiqr(bBOYEYC, gwdHfSOXVOnDbVH);else fEDCZYq += PxSxgaQrSIgMAkUJrGFva(bBOYEY" ascii
    $s12 = "function Fihihup(lFxEBMLfxbVRV) {var UwHif = BTvsfiheVHH.join(ACTYattYOdukOP[7]);var bBOYEYC, gwdHfSOXVOnDbVH, SSJzJTGqJtoFZpkoU" ascii
    $s13 = "function yjlqWTYF(HLvKx,erCBJgFlJsjk,YzSquRr){EjDJFBe=HLvKx.split(YzSquRr);rNEUg = ACTYattYOdukOP[0];for(WpdrbkxNnHGt=0;WpdrbkxN" ascii
    $s14 = "function me(hAajNXWGLpOSpCwMT){return String.fromCharCode(hAajNXWGLpOSpCwMT);}" fullword ascii
    $s15 = "function qcmrYEnjk(awVucHyRfkyS,XTRSPoQ) {var npnlgtaBfqp=[ACTYattYOdukOP[15]];awVucHyRfkyS[npnlgtaBfqp[0]]" fullword ascii
    $s16 = "var NTqnq=function(){return new ActiveXObject(ACTYattYOdukOP[1]);}();" fullword ascii
    $s17 = "(XTRSPoQ,0x1,0x0)}function oYKYGvZ(foLCUgY,oIJigYRFEvQcx,UqfzvOe){var jaAheKpFtbOpfM=foLCUgY.createtextfile(oIJigYRFEvQcx,true);" ascii
    $s18 = "function pdmxmKQF(){return yjlqWTYF(ACTYattYOdukOP[13],[0,3,6],ACTYattYOdukOP[14]);}" fullword ascii
    $s19 = "function PxSxgaQrSIgMAkUJrGFva(jxRBlOdXQ,gdogSPNfgNjCqXKVSeqiI,OZZsYlTKfGFYGKznYWxB){return String.fromCharCode(jxRBlOdXQ,gdogSP" ascii
    $s20 = "function MAWWObiPQg(){return yjlqWTYF(ACTYattYOdukOP[9],[1,5,7],ACTYattYOdukOP[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}