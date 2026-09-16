rule sig_20160527_222b7c70912ea83936facaf2bb607745 {
  meta:
    description = "datamaliciousorder - file 20160527_222b7c70912ea83936facaf2bb607745.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a5c1426f4f81f90d2b32d35c5518a67538071fa8a3616c99c2bc802e64ac7de"

  strings:
    $s1  = "function GtDzjFTYy() {return WScript;}function laYxTcvT(){return DHYSMfUz.ExpandEnvironmentStrings(JViUlmy())}" fullword ascii
    $s2  = "var bFjdPsazWyYYyI = JbizsI.createtextfile(DHYSMfUz.ExpandEnvironmentStrings(hiSNcCLQPPvmqdmLisX[2]+hiSNcCLQPPvmqdmLisX[3])+Stri" ascii
    $s3  = "function RUigGTTUtMUrLx(pfxVjqUabZgszqTlnuca,ZKCOGNXcmpyxVXVAYBKt){return pfxVjqUabZgszqTlnuca.charAt(ZKCOGNXcmpyxVXVAYBKt);}" fullword ascii
    $s4  = "function PlqCPiewJufduZsPXqj(liyqVr,CRiUsRt,hPvrOAzGdfSOrvEMazfnq){return String.fromCharCode(liyqVr,CRiUsRt,hPvrOAzGdfSOrvEMazf" ascii
    $s5  = "var JbizsI=function(){return new ActiveXObject(hiSNcCLQPPvmqdmLisX[0]);}();" fullword ascii
    $s6  = "function EuRKeH(){return kALvwER(hiSNcCLQPPvmqdmLisX[12],[0,3,6],hiSNcCLQPPvmqdmLisX[13]);}" fullword ascii
    $s7  = "TObkegLnFLGKcg = gnwmZnigkWdqiZC & 0xff;if (GqNJhrQgBdxluPudN == 64) DBgrZiCxhEPJszUQPHojqa += Qn(jQPTpgsjLztc);else if (SRhNKPW" ascii
    $s8  = "function PlqCPiewJufduZsPXqj(liyqVr,CRiUsRt,hPvrOAzGdfSOrvEMazfnq){return String.fromCharCode(liyqVr,CRiUsRt,hPvrOAzGdfSOrvEMazf" ascii
    $s9  = "function kALvwER(JBIdgtmfUWoh,IQyFh,eUoZJIoygSEoI){jpkcNXc=JBIdgtmfUWoh.split(eUoZJIoygSEoI);IiYprbsCgwn = hiSNcCLQPPvmqdmLisX[1" ascii
    $s10 = "ng.fromCharCode(92)+hiSNcCLQPPvmqdmLisX[4],true);" fullword ascii
    $s11 = "function TstchssShHUfF(LbuFRDsEI,ryQnVvEoHIQH) {var iznKObYKFaYE=[hiSNcCLQPPvmqdmLisX[15]];LbuFRDsEI[iznKObYKFaYE[0]](ryQnVvEoHI" ascii
    $s12 = "function CIUpkY(kTzMPkQChrzWnGdu,NwDSdmWgnYgQXidgXq){return String.fromCharCode(kTzMPkQChrzWnGdu,NwDSdmWgnYgQXidgXq);}" fullword ascii
    $s13 = "function kALvwER(JBIdgtmfUWoh,IQyFh,eUoZJIoygSEoI){jpkcNXc=JBIdgtmfUWoh.split(eUoZJIoygSEoI);IiYprbsCgwn = hiSNcCLQPPvmqdmLisX[1" ascii
    $s14 = "function CfMeqGalSppvdlZLBaOF(NwvcHSewxlesGOwLkjP,AJZmJVFrFuAwlTzfA){return NwvcHSewxlesGOwLkjP.indexOf(AJZmJVFrFuAwlTzfA);}" fullword ascii
    $s15 = "function hLwTspaQTaFReS(){return kALvwER(hiSNcCLQPPvmqdmLisX[10],[2,4,8,10],hiSNcCLQPPvmqdmLisX[11]);}" fullword ascii
    $s16 = "function cFkNfH(ZxEXffrtBSsae) {var Kbuuc = aZXfsv.join(hiSNcCLQPPvmqdmLisX[6]);var jQPTpgsjLztc, ineEuvHIrtjsnETKAgdfdMzs, BMCJ" ascii
    $s17 = "function JViUlmy(){return kALvwER(hiSNcCLQPPvmqdmLisX[8],[1,5,7],hiSNcCLQPPvmqdmLisX[9]);}" fullword ascii
    $s18 = "lqCPiewJufduZsPXqj(jQPTpgsjLztc, ineEuvHIrtjsnETKAgdfdMzs, BMCJkBTObkegLnFLGKcg);} while (vUwlXy < ZxEXffrtBSsae.length);return " ascii
    $s19 = "function Qn(tLiBzbacuAnNGVCWg){return String.fromCharCode(tLiBzbacuAnNGVCWg);}" fullword ascii
    $s20 = "ijYoKMnJLVGhSRB == 64) DBgrZiCxhEPJszUQPHojqa += CIUpkY(jQPTpgsjLztc, ineEuvHIrtjsnETKAgdfdMzs);else DBgrZiCxhEPJszUQPHojqa += P" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}