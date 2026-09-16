rule sig_20160531_42996efd20ab8e49daff21fb6c56765b {
  meta:
    description = "datamaliciousorder - file 20160531_42996efd20ab8e49daff21fb6c56765b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b039b6ab753814c16d6068c295856fad12adae45f5adf9b9eb7f7cc375929cc"

  strings:
    $s1  = "function BuBTWrCZPWpRmpJ(nvLHtReRTHniA,JjxVFBzNno){return nvLHtReRTHniA.charAt(JjxVFBzNno);}" fullword ascii
    $s2  = "var kaAxSwXcyt=function(){return WScript.CreateObject(fdfMITvCaeuOatMJyVQ[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s3  = "function tjorqRyaaXnMRHr(DXyvTCULdLWJGBLmq,xPzLthjoWIfdBrtJaY){return DXyvTCULdLWJGBLmq.indexOf(xPzLthjoWIfdBrtJaY);}" fullword ascii
    $s4  = "ZQS, kLrQCuKWWWhVAkGBOi);else fwKVyv += yUSbGglFVtE(qFiXXQjgrZCfgEsKoNZQS, kLrQCuKWWWhVAkGBOi, FDcXUMLilsfEgafQrXn);} while (haV" ascii
    $s5  = "function Tt(MaiTphpeUlQuhYdeXQEuFz){return String.fromCharCode(MaiTphpeUlQuhYdeXQEuFz);}" fullword ascii
    $s6  = "f (UHoAP == 64) fwKVyv += Tt(qFiXXQjgrZCfgEsKoNZQS);else if (hRdIzorXaFmew == 64) fwKVyv += dhbOICbymjPWcdyPa(qFiXXQjgrZCfgEsKoN" ascii
    $s7  = "(KHvaSPvWxv,0x1,0x0)}function YuXQhXWotnxC(kmArPSfr,WhrNmrG,rVPFJ){var jBPUwcsqTL=kmArPSfr.createtextfile(WhrNmrG,true);jBPUwcsq" ascii
    $s8  = "yVQ[0];for(OkJveim=0;OkJveim<QlCFBWhcmpLlR.length;OkJveim++) {pjdTxqpbD+=YJPfJzjTuMID[QlCFBWhcmpLlR[OkJveim]];}return pjdTxqpbD." ascii
    $s9  = "XxMrFYX < lTBrjfYPJYsgd.length);return fwKVyv;}" fullword ascii
    $s10 = "function yUSbGglFVtE(lIkWh,oNSIjSCFP,nSrvIiMeIAjGwqJdvD){return String.fromCharCode(lIkWh,oNSIjSCFP,nSrvIiMeIAjGwqJdvD);}" fullword ascii
    $s11 = "(KHvaSPvWxv,0x1,0x0)}function YuXQhXWotnxC(kmArPSfr,WhrNmrG,rVPFJ){var jBPUwcsqTL=kmArPSfr.createtextfile(WhrNmrG,true);jBPUwcsq" ascii
    $s12 = "function dhbOICbymjPWcdyPa(xkKVYzejJBbTlaYfg,OtjetQBUypMCxZid){return String.fromCharCode(xkKVYzejJBbTlaYfg,OtjetQBUypMCxZid);}" fullword ascii
    $s13 = "function ZvdqOgNMl(CuLhULloLLUv,QlCFBWhcmpLlR,fwCXlvKIy){YJPfJzjTuMID=CuLhULloLLUv.split(fwCXlvKIy);pjdTxqpbD = fdfMITvCaeuOatMJ" ascii
    $s14 = "function ZvdqOgNMl(CuLhULloLLUv,QlCFBWhcmpLlR,fwCXlvKIy){YJPfJzjTuMID=CuLhULloLLUv.split(fwCXlvKIy);pjdTxqpbD = fdfMITvCaeuOatMJ" ascii
    $s15 = "function EYwSSb(lTBrjfYPJYsgd) {var AxWagaePQphmUd = TEGPdpcGLRrFEcAiGG.join(fdfMITvCaeuOatMJyVQ[7]);var qFiXXQjgrZCfgEsKoNZQS, " ascii
    $s16 = "var hLUFmNTTrrIQ=function(){return new ActiveXObject(fdfMITvCaeuOatMJyVQ[1]);}();" fullword ascii
    $s17 = "function gXfQWfJ(){return ZvdqOgNMl(fdfMITvCaeuOatMJyVQ[13],[0,3,6],fdfMITvCaeuOatMJyVQ[14]);}" fullword ascii
    $s18 = "function EYwSSb(lTBrjfYPJYsgd) {var AxWagaePQphmUd = TEGPdpcGLRrFEcAiGG.join(fdfMITvCaeuOatMJyVQ[7]);var qFiXXQjgrZCfgEsKoNZQS, " ascii
    $s19 = "function cqEonunVG(){return ZvdqOgNMl(fdfMITvCaeuOatMJyVQ[11],[2,4,8,10],fdfMITvCaeuOatMJyVQ[12]);}" fullword ascii
    $s20 = "function qFostYtauLcAuC(){return ZvdqOgNMl(fdfMITvCaeuOatMJyVQ[9],[1,5,7],fdfMITvCaeuOatMJyVQ[10]);}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}