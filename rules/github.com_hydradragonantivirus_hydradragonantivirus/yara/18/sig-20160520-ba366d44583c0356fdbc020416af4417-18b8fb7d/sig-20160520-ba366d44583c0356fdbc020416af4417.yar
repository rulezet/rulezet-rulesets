rule sig_20160520_ba366d44583c0356fdbc020416af4417 {
  meta:
    description = "datamaliciousorder - file 20160520_ba366d44583c0356fdbc020416af4417.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce47b9b640cf6924e84f9a5916ac3f8283ee6748ca7076ef61a569774886fe2a"

  strings:
    $s1  = "function FsmsPMzl(mSwPJ) {var dClqkNbT=xVkoTNLgPuAMVXCRJpRTMqqz[2];for(var FEsDg=0;FEsDg<mSwPJ;FEsDg++){XOfes+=dClqkNbT.charAt(M" ascii
    $s2  = "function FsmsPMzl(mSwPJ) {var dClqkNbT=xVkoTNLgPuAMVXCRJpRTMqqz[2];for(var FEsDg=0;FEsDg<mSwPJ;FEsDg++){XOfes+=dClqkNbT.charAt(M" ascii
    $s3  = "ath.floor(Math.random()*dClqkNbT.length));}return XOfes;}" fullword ascii
    $s4  = "function ZkFsr(qVqLVH){return new ActiveXObject(qVqLVH);}" fullword ascii
    $s5  = "function faVwi(NcJznTHP,RSwprX,GMgGqpaTg){BqjCR=NcJznTHP.split(GMgGqpaTg);gsJTMxu = xVkoTNLgPuAMVXCRJpRTMqqz[13];for(LtiflbwU=0;" ascii
    $s6  = "function NQspOT(qVqLVH){return qVqLVH.ExpandEnvironmentStrings(xVkoTNLgPuAMVXCRJpRTMqqz[10])}" fullword ascii
    $s7  = "function GSJwR(PVzezIdN,vdwIA,JohoGQcHyO){PVzezIdN.open();PVzezIdN.type = 1;PVzezIdN.write(vdwIA);PVzezIdN.position = 0;PVzezIdN" ascii
    $s8  = "function faVwi(NcJznTHP,RSwprX,GMgGqpaTg){BqjCR=NcJznTHP.split(GMgGqpaTg);gsJTMxu = xVkoTNLgPuAMVXCRJpRTMqqz[13];for(LtiflbwU=0;" ascii
    $s9  = "function Mgrt(cHOqpK,WSsotJD){PjbO = xVkoTNLgPuAMVXCRJpRTMqqz[11].split(xVkoTNLgPuAMVXCRJpRTMqqz[12]);WSsotJD.open(PjbO[0]+PjbO[" ascii
    $s10 = "function PipGeELWS(NYhjTUlII,SHvrIta,GJUCMOiG){" fullword ascii
    $s11 = "2]+PjbO[3], cHOqpK, false);WSsotJD.send();}" fullword ascii
    $s12 = "try{PipGeELWS(QhyBQ[vMNn], GGSjOXL() + xVkoTNLgPuAMVXCRJpRTMqqz[9], 1)}catch(e){}; " fullword ascii
    $s13 = "function Mgrt(cHOqpK,WSsotJD){PjbO = xVkoTNLgPuAMVXCRJpRTMqqz[11].split(xVkoTNLgPuAMVXCRJpRTMqqz[12]);WSsotJD.open(PjbO[0]+PjbO[" ascii
    $s14 = "LtiflbwU<RSwprX.length;LtiflbwU++) {gsJTMxu+=BqjCR[RSwprX[LtiflbwU]];}return gsJTMxu.substring(3,gsJTMxu.length);}" fullword ascii
    $s15 = "function GGSjOXL() {var tJIX=100000;var uWyTKG = 100;return Math.random()*(tJIX-uWyTKG)+uWyTKG;}" fullword ascii
    $s16 = "function GSJwR(PVzezIdN,vdwIA,JohoGQcHyO){PVzezIdN.open();PVzezIdN.type = 1;PVzezIdN.write(vdwIA);PVzezIdN.position = 0;PVzezIdN" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}