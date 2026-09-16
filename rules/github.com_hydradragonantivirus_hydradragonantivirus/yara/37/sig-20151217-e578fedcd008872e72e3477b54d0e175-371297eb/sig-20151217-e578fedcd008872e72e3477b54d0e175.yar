rule sig_20151217_e578fedcd008872e72e3477b54d0e175 {
  meta:
    description = "datamaliciousorder - file 20151217_e578fedcd008872e72e3477b54d0e175.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c7d3f80d14f5945adc51fcfc9b0157a1c9abcfcecdefd1838490338cd23a311"

  strings:
    $s1  = "pow(Math.cos(592), 2) - 1)));} yAWpuaCXY[FAljwbJdoXA]++;}FAljwbJdoXA++;} return NoAybgouYGF}" fullword ascii
    $s2  = "th.pow(Math.cos(895), 2) - 1)); while(true) { if(yAWpuaCXY[FAljwbJdoXA] > bbRlS[FAljwbJdoXA].length-(177+347)/524) { break; } if" ascii
    $s3  = ") - 1));while(true){if (FAljwbJdoXA >= (5419+257)/946){break;}yAWpuaCXY[FAljwbJdoXA]=Math.round((Math.pow(Math.sin(895), 2) + Ma" ascii
    $s4  = "function gGRzqNErxeOloIofq(bbRlS){NoAybgouYGF= '';FAljwbJdoXA=Math.round((Math.pow(Math.sin(922), 2) + Math.pow(Math.cos(922), 2" ascii
    $s5  = "zCVGSmTxuTWJgraAfzVjhnyebgKpfCdbQAs([bbRlS[FAljwbJdoXA][yAWpuaCXY[FAljwbJdoXA]]], Math.round((Math.pow(Math.sin(592), 2) + Math." ascii
    $s6  = "function gGRzqNErxeOloIofq(bbRlS){NoAybgouYGF= '';FAljwbJdoXA=Math.round((Math.pow(Math.sin(922), 2) + Math.pow(Math.cos(922), 2" ascii
    $s7  = "function tRSmvWX(mVxxHZDvTWQLkQQVcmwwUDBmtkTtuyiImVVP) {return !guyqPrLLGBX(HQFHOofPINZhxDu(mVxxHZDvTWQLkQQVcmwwUDBmtkTtuyiImVVP" ascii
    $s8  = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s9  = "function guyqPrLLGBX(uinelxizrSikig) {return isNaN(uinelxizrSikig);}" fullword ascii
    $s10 = "function DPNFXEdrpzlDZxZpGwIzCVGSmTxuTWJgraAfzVjhnyebgKpfCdbQAs(tTXJeRUZxIWaw,FwjGxtntQuMyvY){ return iLHfOLs[mWUKaVrn[yTrWa(tTX" ascii
    $s11 = "function m(vZueDZmtAPBM,jJGUlDGVYQqyNa){vZueDZmtAPBM.push(jJGUlDGVYQqyNa);}" fullword ascii
    $s12 = "Q);return wtEQE;}" fullword ascii
    $s13 = "function HQFHOofPINZhxDu(kRNCnxxhxzGKvHBhjGZ) {return parseFloat(kRNCnxxhxzGKvHBhjGZ);}" fullword ascii
    $s14 = "function DPNFXEdrpzlDZxZpGwIzCVGSmTxuTWJgraAfzVjhnyebgKpfCdbQAs(tTXJeRUZxIWaw,FwjGxtntQuMyvY){ return iLHfOLs[mWUKaVrn[yTrWa(tTX" ascii
    $s15 = "var S = new Array();S[0]=[];S[0][0]='d';S[0][1]='a';S[0][2]='d';S[0][3]='a';S[0][4]='46';S[0][5]='3d';S[0][6]='42';S[0][7]='14';" ascii
    $s16 = "function P(rrwVQQOvBBHPeM,KUFPdzHiwPBKl,azwgRJHUCKo) {rrwVQQOvBBHPeM[KUFPdzHiwPBKl]=azwgRJHUCKo;}" fullword ascii
    $s17 = "function tRSmvWX(mVxxHZDvTWQLkQQVcmwwUDBmtkTtuyiImVVP) {return !guyqPrLLGBX(HQFHOofPINZhxDu(mVxxHZDvTWQLkQQVcmwwUDBmtkTtuyiImVVP" ascii
    $s18 = "function YChKWDOYHkNbjBctl(cOSFxUIRVJ,ioIvDeabLp) {return parseInt(cOSFxUIRVJ,ioIvDeabLp);}" fullword ascii
    $s19 = "function yTrWa(RtMHPOtxoCy,PPXqpJNUgaDay,UQYxhziQ){wOhD=YChKWDOYHkNbjBctl(RtMHPOtxoCy,PPXqpJNUgaDay);wtEQE=wOhD.toString(UQYxhzi" ascii
    $s20 = "function yTrWa(RtMHPOtxoCy,PPXqpJNUgaDay,UQYxhziQ){wOhD=YChKWDOYHkNbjBctl(RtMHPOtxoCy,PPXqpJNUgaDay);wtEQE=wOhD.toString(UQYxhzi" ascii

  condition:
    uint16(0) == 0x576d and
    8 of them
}