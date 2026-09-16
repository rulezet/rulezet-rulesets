rule sig_20151217_4ed0949fa0f08b893e1fbcfd030a70e9 {
  meta:
    description = "datamaliciousorder - file 20151217_4ed0949fa0f08b893e1fbcfd030a70e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "243858473766145926d39eebb543bf6c8617b0eb544527f984a71bd2fe077705"

  strings:
    $s1  = "function xAZWYgRpJnVhyEDwh(dWHsR){BoVXYMeqjsb= '';GrIIIpAZfqi=Math.round((Math.pow(Math.sin(133), 2) + Math.pow(Math.cos(133), 2" ascii
    $s2  = ") - 1));while(true){if (GrIIIpAZfqi >= (4729+689)/903){break;}YKYqTELMf[GrIIIpAZfqi]=Math.round((Math.pow(Math.sin(779), 2) + Ma" ascii
    $s3  = "th.pow(Math.cos(779), 2) - 1)); while(true) { if(YKYqTELMf[GrIIIpAZfqi] > dWHsR[GrIIIpAZfqi].length-(-252+501)/249) { break; } i" ascii
    $s4  = "pow(Math.cos(595), 2) - 1)));} YKYqTELMf[GrIIIpAZfqi]++;}GrIIIpAZfqi++;} return BoVXYMeqjsb}" fullword ascii
    $s5  = "VTNnkKRHNdFzgRbYdDtwIhEfAwsTgmiYmhk([dWHsR[GrIIIpAZfqi][YKYqTELMf[GrIIIpAZfqi]]], Math.round((Math.pow(Math.sin(595), 2) + Math." ascii
    $s6  = "function xAZWYgRpJnVhyEDwh(dWHsR){BoVXYMeqjsb= '';GrIIIpAZfqi=Math.round((Math.pow(Math.sin(133), 2) + Math.pow(Math.cos(133), 2" ascii
    $s7  = "function FpPmZiP(LEnpSmAepNfiiiQBLZcunQaWnakIUDJsqWsS) {return !YeqDsGirRXK(wlCJumKfYfZfogO(LEnpSmAepNfiiiQBLZcunQaWnakIUDJsqWsS" ascii
    $s8  = "O);return tWWik;}" fullword ascii
    $s9  = "function L(eeKqTgbbnIJc,FmDJBtOnbPCntp){eeKqTgbbnIJc.push(FmDJBtOnbPCntp);}" fullword ascii
    $s10 = "function kHiLa(jBiwMixSahd,oBWpKrhYBNimQ,LmIMtsXO){ZNbN=HSzWfxDdHJglUFdvW(jBiwMixSahd,oBWpKrhYBNimQ);tWWik=ZNbN.toString(LmIMtsX" ascii
    $s11 = "function I(ZObAhUmKBghhqK,uSNDYVpjoMgUb,HfqmVzYFCHR) {ZObAhUmKBghhqK[uSNDYVpjoMgUb]=HfqmVzYFCHR;}" fullword ascii
    $s12 = "function CYFAArlPTpWRVeZgXnsVTNnkKRHNdFzgRbYdDtwIhEfAwsTgmiYmhk(EBQdQgVEmJKto,RrovQtIgtgOQGX){ return KDvwhUo[unCOLcpm[kHiLa(EBQ" ascii
    $s13 = "function kHiLa(jBiwMixSahd,oBWpKrhYBNimQ,LmIMtsXO){ZNbN=HSzWfxDdHJglUFdvW(jBiwMixSahd,oBWpKrhYBNimQ);tWWik=ZNbN.toString(LmIMtsX" ascii
    $s14 = "function YeqDsGirRXK(NqHsnfnXrSrxWS) {return isNaN(NqHsnfnXrSrxWS);}" fullword ascii
    $s15 = "function wlCJumKfYfZfogO(KJGjIvpqcjMhiOvtZtx) {return parseFloat(KJGjIvpqcjMhiOvtZtx);}" fullword ascii
    $s16 = "function FpPmZiP(LEnpSmAepNfiiiQBLZcunQaWnakIUDJsqWsS) {return !YeqDsGirRXK(wlCJumKfYfZfogO(LEnpSmAepNfiiiQBLZcunQaWnakIUDJsqWsS" ascii
    $s17 = "var y = new Array();y[0]=[];y[0][0]='d';y[0][1]='a';y[0][2]='d';y[0][3]='a';y[0][4]='46';y[0][5]='3d';y[0][6]='42';y[0][7]='14';" ascii
    $s18 = "function CYFAArlPTpWRVeZgXnsVTNnkKRHNdFzgRbYdDtwIhEfAwsTgmiYmhk(EBQdQgVEmJKto,RrovQtIgtgOQGX){ return KDvwhUo[unCOLcpm[kHiLa(EBQ" ascii
    $s19 = "function HSzWfxDdHJglUFdvW(UsGZhiLLTI,JevwWLNwjL) {return parseInt(UsGZhiLLTI,JevwWLNwjL);}" fullword ascii
    $s20 = "function AbINRJdwdaLEDir(HvEnLIXWpYeuFhOMo,MsECVfqpVmNSWFFJyiuiefINtGiIRppTmC,thaOxgLmJPhgcHlSPsZDagXvljsbIQNvkcA){eval(HvEnLIXW" ascii

  condition:
    uint16(0) == 0x6e75 and
    8 of them
}