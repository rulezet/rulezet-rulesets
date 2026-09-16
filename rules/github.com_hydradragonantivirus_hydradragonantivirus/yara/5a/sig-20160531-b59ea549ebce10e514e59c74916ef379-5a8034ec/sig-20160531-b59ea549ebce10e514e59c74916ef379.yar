rule sig_20160531_b59ea549ebce10e514e59c74916ef379 {
  meta:
    description = "datamaliciousorder - file 20160531_b59ea549ebce10e514e59c74916ef379.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3012930fdc85e2d86d8c24335e5d3f06db0ffb7751df645a297affc5a0c76e33"

  strings:
    $s1  = "var gkXvymwT=function(){return WScript.CreateObject(cKMDlwdBn[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function ZlqkRvaTIPnjhgVNslhma(KBAZhCJMAchHSrHHmuw,ibberOlTNLe){return KBAZhCJMAchHSrHHmuw.charAt(ibberOlTNLe);}" fullword ascii
    $s3  = "function mqbLi(mytZefkQRBcb,wmOtHYE){return String.fromCharCode(mytZefkQRBcb,wmOtHYE);}" fullword ascii
    $s4  = "var fJeDAYeSKuCj=function(){return new ActiveXObject(cKMDlwdBn[1]);}();" fullword ascii
    $s5  = "function ohXbevdIHMBxhm(){return oqmkoMqSlB(cKMDlwdBn[13],[0,3,6],cKMDlwdBn[14]);}" fullword ascii
    $s6  = "function mYEAntT(){return oqmkoMqSlB(cKMDlwdBn[9],[1,5,7],cKMDlwdBn[10]);}" fullword ascii
    $s7  = "function LpqhCu(JFdlNGtONyNXL,nZdoRmCgm) {var ugDIblOB=[cKMDlwdBn[15]];JFdlNGtONyNXL[ugDIblOB[0]]" fullword ascii
    $s8  = "function SGfyVLkWS(){return gkXvymwT.ExpandEnvironmentStrings(mYEAntT())}" fullword ascii
    $s9  = "function mabPqmiOSXxNxBLuNcUlwn(ylPtMHeXkparycQMtheRwOk,LyyUNOAhXzOROJSqxKl,fSuKbusquh){return String.fromCharCode(ylPtMHeXkpary" ascii
    $s10 = "BbWnZ=0;BbWnZ<AbHsUTGF.length;BbWnZ++) {RcviTqkGnqFU+=NrJTqLacuhAs[AbHsUTGF[BbWnZ]];}return RcviTqkGnqFU.substring(3,RcviTqkGnqF" ascii
    $s11 = "UINIJovTNsKwKS == 64) RzNSkVzAgCDqQCpbjeOsqPV += ON(FYhHzjiLkDrAemkTM);else if (soKZWyj == 64) RzNSkVzAgCDqQCpbjeOsqPV += mqbLi(" ascii
    $s12 = "function mabPqmiOSXxNxBLuNcUlwn(ylPtMHeXkparycQMtheRwOk,LyyUNOAhXzOROJSqxKl,fSuKbusquh){return String.fromCharCode(ylPtMHeXkpary" ascii
    $s13 = "function oqmkoMqSlB(xKhKQWgavioXBr,AbHsUTGF,dPJureI){NrJTqLacuhAs=xKhKQWgavioXBr.split(dPJureI);RcviTqkGnqFU = cKMDlwdBn[0];for(" ascii
    $s14 = "function ON(rPqPNlXr){return String.fromCharCode(rPqPNlXr);}" fullword ascii
    $s15 = "function HZhAJSjy(){return oqmkoMqSlB(cKMDlwdBn[11],[2,4,8,10],cKMDlwdBn[12]);}" fullword ascii
    $s16 = "function JadSKY(lFTEzanPaQJRm) {var UrdzoozuPVlEJvC = BIPMPRxSqiQZQxskvfIPeUov.join(cKMDlwdBn[7]);var FYhHzjiLkDrAemkTM, ufEEhqH" ascii
    $s17 = "function xdCTpdGejuVwgy(hZkUvH,oUMbXrqzMixaEfG){return hZkUvH.indexOf(oUMbXrqzMixaEfG);}" fullword ascii
    $s18 = "KAiTuJopm, nwNMmENntlanTc);} while (pHjiIaSTCrEQ < lFTEzanPaQJRm.length);return RzNSkVzAgCDqQCpbjeOsqPV;}" fullword ascii
    $s19 = "push(\"v\");BIPMPRxSqiQZQxskvfIPeUov.push(\"w\");BIPMPRxSqiQZQxskvfIPeUov.push(\"x\");BIPMPRxSqiQZQxskvfIPeUov.push(\"y\");BIPMP" ascii
    $s20 = "function JadSKY(lFTEzanPaQJRm) {var UrdzoozuPVlEJvC = BIPMPRxSqiQZQxskvfIPeUov.join(cKMDlwdBn[7]);var FYhHzjiLkDrAemkTM, ufEEhqH" ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}