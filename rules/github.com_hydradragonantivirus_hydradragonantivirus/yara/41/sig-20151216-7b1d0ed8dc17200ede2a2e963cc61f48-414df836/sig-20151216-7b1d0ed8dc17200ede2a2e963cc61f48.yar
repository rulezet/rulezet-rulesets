rule sig_20151216_7b1d0ed8dc17200ede2a2e963cc61f48 {
  meta:
    description = "datamaliciousorder - file 20151216_7b1d0ed8dc17200ede2a2e963cc61f48.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95f0e478b0a4cb5f9fdbd26e9a7d7d64fd964755d246a8c20bf177f2c6c4cbdb"

  strings:
    $s1  = "Math.cos(71), 2) - 1)));} bNSMObLTL[RoBNyXgLfcT]++;}RoBNyXgLfcT++;} return weBovxPNbyh}" fullword ascii
    $s2  = "th.pow(Math.cos(928), 2) - 1)); while(true) { if(bNSMObLTL[RoBNyXgLfcT] > lwyJG[RoBNyXgLfcT].length-(-38+100)/62) { break; } if " ascii
    $s3  = "function afHzGZHUfSEbIGvaS(lwyJG){weBovxPNbyh= '';RoBNyXgLfcT=Math.round((Math.pow(Math.sin(944), 2) + Math.pow(Math.cos(944), 2" ascii
    $s4  = ") - 1));while(true){if (RoBNyXgLfcT >= (1258+386)/274){break;}bNSMObLTL[RoBNyXgLfcT]=Math.round((Math.pow(Math.sin(928), 2) + Ma" ascii
    $s5  = "function afHzGZHUfSEbIGvaS(lwyJG){weBovxPNbyh= '';RoBNyXgLfcT=Math.round((Math.pow(Math.sin(944), 2) + Math.pow(Math.cos(944), 2" ascii
    $s6  = "function BlFqvSL(FMIoaGPfwqJTCtqGOGFKXGqEcVGMoSEuFYPn) {return !UDPMLztGgYN(JSrWkNbUtYQEXyQ(FMIoaGPfwqJTCtqGOGFKXGqEcVGMoSEuFYPn" ascii
    $s7  = "function kNOhI(jguVnKZJbbn,wlmaOYAMCCBPD,ENsADiRM){sMgM=wLjjubCOYNapNoVew(jguVnKZJbbn,wlmaOYAMCCBPD);IEHIM=sMgM.toString(ENsADiR" ascii
    $s8  = "function BOztQKUprZrTlzo(pbSJfrxhkUtjUXpXv,MeaXGNppnWwPsuzBxlHcYuUFVAGInXRUyp,iMYMAFpSrAAjsemcnfdQDywqtzrXBOSXsoY){eval(pbSJfrxh" ascii
    $s9  = "function JSrWkNbUtYQEXyQ(tUuPUUUllTTvVQEcNTC) {return parseFloat(tUuPUUUllTTvVQEcNTC);}" fullword ascii
    $s10 = "var m = new Array();m[0]=[];m[0][0]='d';m[0][1]='a';m[0][2]='d';m[0][3]='a';m[0][4]='46';m[0][5]='3d';m[0][6]='42';m[0][7]='14';" ascii
    $s11 = "function BOztQKUprZrTlzo(pbSJfrxhkUtjUXpXv,MeaXGNppnWwPsuzBxlHcYuUFVAGInXRUyp,iMYMAFpSrAAjsemcnfdQDywqtzrXBOSXsoY){eval(pbSJfrxh" ascii
    $s12 = "function wLjjubCOYNapNoVew(SqtiZiPlwz,vbCwNCDqcm) {return parseInt(SqtiZiPlwz,vbCwNCDqcm);}" fullword ascii
    $s13 = "var m = new Array();m[0]=[];m[0][0]='d';m[0][1]='a';m[0][2]='d';m[0][3]='a';m[0][4]='46';m[0][5]='3d';m[0][6]='42';m[0][7]='14';" ascii
    $s14 = "function kNOhI(jguVnKZJbbn,wlmaOYAMCCBPD,ENsADiRM){sMgM=wLjjubCOYNapNoVew(jguVnKZJbbn,wlmaOYAMCCBPD);IEHIM=sMgM.toString(ENsADiR" ascii
    $s15 = "function r(AFkNnJjJRrIE,CXFaqNrhaCmJmI){AFkNnJjJRrIE.push(CXFaqNrhaCmJmI);}" fullword ascii
    $s16 = "function fBltXqXiPHtWUTlphIeRnhwPFhpMDMOELeGolIoHhseuCHpumWVfxJ(TgOWATOCvTSgU,IgtMHnydDPLwBH){ return abvJDDc[sdINyYsH[kNOhI(TgO" ascii
    $s17 = "function UDPMLztGgYN(XfsfouScPTVnui) {return isNaN(XfsfouScPTVnui);}" fullword ascii
    $s18 = "function BlFqvSL(FMIoaGPfwqJTCtqGOGFKXGqEcVGMoSEuFYPn) {return !UDPMLztGgYN(JSrWkNbUtYQEXyQ(FMIoaGPfwqJTCtqGOGFKXGqEcVGMoSEuFYPn" ascii
    $s19 = "function fBltXqXiPHtWUTlphIeRnhwPFhpMDMOELeGolIoHhseuCHpumWVfxJ(TgOWATOCvTSgU,IgtMHnydDPLwBH){ return abvJDDc[sdINyYsH[kNOhI(TgO" ascii
    $s20 = "M);return IEHIM;}" fullword ascii

  condition:
    uint16(0) == 0x6473 and
    8 of them
}