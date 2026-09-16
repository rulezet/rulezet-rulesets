rule sig_20160527_9427cae2b0339bf92ab95981d324a53f {
  meta:
    description = "datamaliciousorder - file 20160527_9427cae2b0339bf92ab95981d324a53f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a01a2c671465373a4932aad04b2264e1de5de2e91966437e379004fc07b98abe"

  strings:
    $s1  = "function zrVJUQUY() {return WScript;}function WuPYqaU(){return sRlwHB.ExpandEnvironmentStrings(nYyEDtD())}" fullword ascii
    $s2  = "function voHTMtsnzGh(fnxopPwOaktIHrrr,PDRAzAAYBpBhaE){return fnxopPwOaktIHrrr.charAt(PDRAzAAYBpBhaE);}" fullword ascii
    $s3  = "qxViYDkvlbC & 0xff;if (gEHpYhYyEdOU == 64) ueMqcDYeajqJVqwYgvtyV += OB(OgTETGIZiEgbkRFBbzHtwm);else if (IkTSadjmtTehiJQaKHbAk ==" ascii
    $s4  = "function OOMDmBBdShXKikoibIkKhu(qrBcWCQqgkfQMxWSp,BykcLUqmoMptceWsbRo,ACfFOKEpIoqFzsEymhkz){return String.fromCharCode(qrBcWCQqg" ascii
    $s5  = "function QnaCuYttiTlRP(sBtSXiJFMjbhK) {var YajdrBxLpirS = IxpNRR.join(LvWIRYvHvlVOFkQTzaAwQWy[6]);var OgTETGIZiEgbkRFBbzHtwm, gQ" ascii
    $s6  = "function nYyEDtD(){return hhsWAXcCqDL(LvWIRYvHvlVOFkQTzaAwQWy[8],[1,5,7],LvWIRYvHvlVOFkQTzaAwQWy[9]);}" fullword ascii
    $s7  = "function aNLAVulKHCOor(nOdMDTTItAdrTa,RkzMTKtOPQG) {var aEuyYueWIbCoV=[LvWIRYvHvlVOFkQTzaAwQWy[15]];nOdMDTTItAdrTa[aEuyYueWIbCoV" ascii
    $s8  = "function OB(YOmaxRqdYOzOYSFfG){return String.fromCharCode(YOmaxRqdYOzOYSFfG);}" fullword ascii
    $s9  = "function aNLAVulKHCOor(nOdMDTTItAdrTa,RkzMTKtOPQG) {var aEuyYueWIbCoV=[LvWIRYvHvlVOFkQTzaAwQWy[15]];nOdMDTTItAdrTa[aEuyYueWIbCoV" ascii
    $s10 = "function OOMDmBBdShXKikoibIkKhu(qrBcWCQqgkfQMxWSp,BykcLUqmoMptceWsbRo,ACfFOKEpIoqFzsEymhkz){return String.fromCharCode(qrBcWCQqg" ascii
    $s11 = "function bpGAJoQNd(MVqGp,QiXVctEKPNEhgfpMexNW){return MVqGp.indexOf(QiXVctEKPNEhgfpMexNW);}" fullword ascii
    $s12 = "function hhsWAXcCqDL(PGlOutCvguC,AcZpeEtEwi,vBcvDaTnyY){gYawfop=PGlOutCvguC.split(vBcvDaTnyY);PJyrWMaf = LvWIRYvHvlVOFkQTzaAwQWy" ascii
    $s13 = "[14];for(fezEnB=0;fezEnB<AcZpeEtEwi.length;fezEnB++) {PJyrWMaf+=gYawfop[AcZpeEtEwi[fezEnB]];}return PJyrWMaf.substring(3,PJyrWMa" ascii
    $s14 = "var GssEjbREcFrk = GDDSgtrdRv.createtextfile(sRlwHB.ExpandEnvironmentStrings(LvWIRYvHvlVOFkQTzaAwQWy[2]+LvWIRYvHvlVOFkQTzaAwQWy[" ascii
    $s15 = " 64) ueMqcDYeajqJVqwYgvtyV += nsqJNi(OgTETGIZiEgbkRFBbzHtwm, gQDShjheT);else ueMqcDYeajqJVqwYgvtyV += OOMDmBBdShXKikoibIkKhu(OgT" ascii
    $s16 = "function hhsWAXcCqDL(PGlOutCvguC,AcZpeEtEwi,vBcvDaTnyY){gYawfop=PGlOutCvguC.split(vBcvDaTnyY);PJyrWMaf = LvWIRYvHvlVOFkQTzaAwQWy" ascii
    $s17 = "function zZWOGVwpXzPxb(){return hhsWAXcCqDL(LvWIRYvHvlVOFkQTzaAwQWy[12],[0,3,6],LvWIRYvHvlVOFkQTzaAwQWy[13]);}" fullword ascii
    $s18 = "3])+String.fromCharCode(92)+LvWIRYvHvlVOFkQTzaAwQWy[4],true);" fullword ascii
    $s19 = "function nsqJNi(IruvjjcBedHSwKi,qIRBbsLEmVmLeYTuxSP){return String.fromCharCode(IruvjjcBedHSwKi,qIRBbsLEmVmLeYTuxSP);}" fullword ascii
    $s20 = "function JafVluazBA(){return hhsWAXcCqDL(LvWIRYvHvlVOFkQTzaAwQWy[10],[2,4,8,10],LvWIRYvHvlVOFkQTzaAwQWy[11]);}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}