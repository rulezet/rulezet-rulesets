rule sig_20160531_63b79d88c01099bd7e0662b492b492c4 {
  meta:
    description = "datamaliciousorder - file 20160531_63b79d88c01099bd7e0662b492b492c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c0edff7f7d47d834bdd8af8cf694b05ce0f244dd54f4b1fba77b2434a44fc16b"

  strings:
    $s1  = "var LCbfWOSAj=function(){return WScript.CreateObject(jkKDLdWOZGjZFY[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ImDdeUAViwqHm(ZahVBUVPqRiRwvcNvkVZef,imWpCUdm){return ZahVBUVPqRiRwvcNvkVZef.charAt(imWpCUdm);}" fullword ascii
    $s3  = "aavFbhWLdTrK.length);return CWKxruaPPJxpGfaV;}" fullword ascii
    $s4  = "(vvVobBbtfB,0x1,0x0)}function JTNTYONyAhOdIX(OptEkdLZDEqQZZ,THfCTEGpX,zzuRHuF){var sHRizaLvQx=OptEkdLZDEqQZZ.createtextfile(THfC" ascii
    $s5  = "Hpi=0;qGeBuCPDWqCHpi<zoLezWyhmpHN.length;qGeBuCPDWqCHpi++) {awPphLyuF+=AhgrgQibQ[zoLezWyhmpHN[qGeBuCPDWqCHpi]];}return awPphLyuF" ascii
    $s6  = " == 64) CWKxruaPPJxpGfaV += zk(lMljuMjooXzLTD);else if (hBMCzMxwGbzrtemKEXNceGZ == 64) CWKxruaPPJxpGfaV += xYXQImGxqigQxsBDLXwax" ascii
    $s7  = "function ToeEZXqcOF(ZybPytmZ,ZksZcfYxrDEacMFnAvYi,sPshaBXSEJYbkMeInV){return String.fromCharCode(ZybPytmZ,ZksZcfYxrDEacMFnAvYi,s" ascii
    $s8  = "function xYXQImGxqigQxsBDLXwaxN(DfIxP,TMNvWgJr){return String.fromCharCode(DfIxP,TMNvWgJr);}" fullword ascii
    $s9  = "(vvVobBbtfB,0x1,0x0)}function JTNTYONyAhOdIX(OptEkdLZDEqQZZ,THfCTEGpX,zzuRHuF){var sHRizaLvQx=OptEkdLZDEqQZZ.createtextfile(THfC" ascii
    $s10 = "function BDtVMkLB(){return kaTteunlzmOLLq(jkKDLdWOZGjZFY[9],[1,5,7],jkKDLdWOZGjZFY[10]);}" fullword ascii
    $s11 = "function kaTteunlzmOLLq(tFGlyiq,zoLezWyhmpHN,tuSuB){AhgrgQibQ=tFGlyiq.split(tuSuB);awPphLyuF = jkKDLdWOZGjZFY[0];for(qGeBuCPDWqC" ascii
    $s12 = "function XmWljvowDq(){return kaTteunlzmOLLq(jkKDLdWOZGjZFY[13],[0,3,6],jkKDLdWOZGjZFY[14]);}" fullword ascii
    $s13 = "function hnuubYUMB(){return kaTteunlzmOLLq(jkKDLdWOZGjZFY[11],[2,4,8,10],jkKDLdWOZGjZFY[12]);}" fullword ascii
    $s14 = "function ToeEZXqcOF(ZybPytmZ,ZksZcfYxrDEacMFnAvYi,sPshaBXSEJYbkMeInV){return String.fromCharCode(ZybPytmZ,ZksZcfYxrDEacMFnAvYi,s" ascii
    $s15 = "function kaTteunlzmOLLq(tFGlyiq,zoLezWyhmpHN,tuSuB){AhgrgQibQ=tFGlyiq.split(tuSuB);awPphLyuF = jkKDLdWOZGjZFY[0];for(qGeBuCPDWqC" ascii
    $s16 = "var IyUpL=function(){return new ActiveXObject(jkKDLdWOZGjZFY[1]);}();" fullword ascii
    $s17 = "function lbKytHiNfgoIcF(XifMhZ,vvVobBbtfB) {var UXKBArEFxQHAB=[jkKDLdWOZGjZFY[15]];XifMhZ[UXKBArEFxQHAB[0]]" fullword ascii
    $s18 = "TEGpX,true);sHRizaLvQx.WriteLine(zzuRHuF);sHRizaLvQx.Close();}" fullword ascii
    $s19 = "function DCqBaqWSZSPBeM(MaavFbhWLdTrK) {var XfCVgkUlPCexlvVYKi = yVAkGPWtTjKuuQsHLMU.join(jkKDLdWOZGjZFY[7]);var lMljuMjooXzLTD," ascii
    $s20 = "function DCqBaqWSZSPBeM(MaavFbhWLdTrK) {var XfCVgkUlPCexlvVYKi = yVAkGPWtTjKuuQsHLMU.join(jkKDLdWOZGjZFY[7]);var lMljuMjooXzLTD," ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}