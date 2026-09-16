rule sig_20151216_1cca17a8ee7647a41ca3471355a81bd0 {
  meta:
    description = "datamaliciousorder - file 20151216_1cca17a8ee7647a41ca3471355a81bd0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b33402d14f0b62ec9190454acb2725a32e1f94b11339b646853df5decb52d80f"

  strings:
    $s1  = "function YQXkSbKNtPXMMoNTL(JTvHY){QVVqYVRRDdy= '';IYOBLhExuTL=Math.round((Math.pow(Math.sin(849), 2) + Math.pow(Math.cos(849), 2" ascii
    $s2  = "th.pow(Math.cos(824), 2) - 1)); while(true) { if(fDtJmYHRC[IYOBLhExuTL] > JTvHY[IYOBLhExuTL].length-(70+453)/523) { break; } if " ascii
    $s3  = ") - 1));while(true){if (IYOBLhExuTL >= (3803+805)/768){break;}fDtJmYHRC[IYOBLhExuTL]=Math.round((Math.pow(Math.sin(824), 2) + Ma" ascii
    $s4  = "(Math.cos(255), 2) - 1)));} fDtJmYHRC[IYOBLhExuTL]++;}IYOBLhExuTL++;} return QVVqYVRRDdy}" fullword ascii
    $s5  = "function YQXkSbKNtPXMMoNTL(JTvHY){QVVqYVRRDdy= '';IYOBLhExuTL=Math.round((Math.pow(Math.sin(849), 2) + Math.pow(Math.cos(849), 2" ascii
    $s6  = "function SbqklIt(TTAzOnxOieGhrDZgnxTVeOOrcZauVmmCrNCw) {return !JNoeemUemmt(DmwhqEdlojkeeTM(TTAzOnxOieGhrDZgnxTVeOOrcZauVmmCrNCw" ascii
    $s7  = "function DmwhqEdlojkeeTM(oTjupyxqZAWJhlyemdk) {return parseFloat(oTjupyxqZAWJhlyemdk);}" fullword ascii
    $s8  = "function wbYxBFsmkEOpTMDtSfalmLMBKFWMytMVLsOvffbzlgmgytbXnvrPDi(BVDkVpVgaoNzS,ahTxExTLLartMx){ return fynGbzf[CJQCrnxA[ywFNQ(BVD" ascii
    $s9  = "function wbYxBFsmkEOpTMDtSfalmLMBKFWMytMVLsOvffbzlgmgytbXnvrPDi(BVDkVpVgaoNzS,ahTxExTLLartMx){ return fynGbzf[CJQCrnxA[ywFNQ(BVD" ascii
    $s10 = "h);return tigkG;}" fullword ascii
    $s11 = "function TSNachGTtsjU(qytFDOKeRuvfH) {return isFinite(qytFDOKeRuvfH);}" fullword ascii
    $s12 = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s13 = "function rgKzZvIdSzlfiXXyI(LeLHVDAAHN,zfaNnNjxZZ) {return parseInt(LeLHVDAAHN,zfaNnNjxZZ);}" fullword ascii
    $s14 = "function g(kZvDwIDSYKbq,frggMMJCjYuYus){kZvDwIDSYKbq.push(frggMMJCjYuYus);}" fullword ascii
    $s15 = "function F(fUgcuMSSdATPbG,xfEMFlyUCckDR,RZozYqLbMQC) {fUgcuMSSdATPbG[xfEMFlyUCckDR]=RZozYqLbMQC;}" fullword ascii
    $s16 = "function ywFNQ(rAwiTIcNNeB,bvjklqJlRAGLn,CqqqsOuh){HJaL=rgKzZvIdSzlfiXXyI(rAwiTIcNNeB,bvjklqJlRAGLn);tigkG=HJaL.toString(CqqqsOu" ascii
    $s17 = "function JNoeemUemmt(SLvxXkKzRRYiqJ) {return isNaN(SLvxXkKzRRYiqJ);}" fullword ascii
    $s18 = "var u = new Array();u[0]=[];u[0][0]='d';u[0][1]='a';u[0][2]='d';u[0][3]='a';u[0][4]='46';u[0][5]='3d';u[0][6]='42';u[0][7]='14';" ascii
    $s19 = "function SbqklIt(TTAzOnxOieGhrDZgnxTVeOOrcZauVmmCrNCw) {return !JNoeemUemmt(DmwhqEdlojkeeTM(TTAzOnxOieGhrDZgnxTVeOOrcZauVmmCrNCw" ascii
    $s20 = "function ywFNQ(rAwiTIcNNeB,bvjklqJlRAGLn,CqqqsOuh){HJaL=rgKzZvIdSzlfiXXyI(rAwiTIcNNeB,bvjklqJlRAGLn);tigkG=HJaL.toString(CqqqsOu" ascii

  condition:
    uint16(0) == 0x4a43 and
    8 of them
}