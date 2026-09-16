rule sig_20151217_3c1f15fc9140e0c56de905b656cdfc45 {
  meta:
    description = "datamaliciousorder - file 20151217_3c1f15fc9140e0c56de905b656cdfc45.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89d4f5585a503786801e00a0f51e1459ce0f3cadb9103c84fc5798b5d7894619"

  strings:
    $s1  = ") - 1));while(true){if (IYRDVtguKCw >= (4582+482)/844){break;}cPabpJgZs[IYRDVtguKCw]=Math.round((Math.pow(Math.sin(499), 2) + Ma" ascii
    $s2  = "function JxdsbRlSERSnCHbfB(QZPnp){HjpycfkfRSS= '';IYRDVtguKCw=Math.round((Math.pow(Math.sin(737), 2) + Math.pow(Math.cos(737), 2" ascii
    $s3  = "th.pow(Math.cos(499), 2) - 1)); while(true) { if(cPabpJgZs[IYRDVtguKCw] > QZPnp[IYRDVtguKCw].length-(-315+723)/408) { break; } i" ascii
    $s4  = "pow(Math.cos(616), 2) - 1)));} cPabpJgZs[IYRDVtguKCw]++;}IYRDVtguKCw++;} return HjpycfkfRSS}" fullword ascii
    $s5  = "function JxdsbRlSERSnCHbfB(QZPnp){HjpycfkfRSS= '';IYRDVtguKCw=Math.round((Math.pow(Math.sin(737), 2) + Math.pow(Math.cos(737), 2" ascii
    $s6  = "JLpNYZvogjZIPzmZjNFtvMcpSzsnkKDBoWc([QZPnp[IYRDVtguKCw][cPabpJgZs[IYRDVtguKCw]]], Math.round((Math.pow(Math.sin(616), 2) + Math." ascii
    $s7  = "function rJKKGAg(PjvRkpijDJvfyqjqyXyALgUBBIjCQsYTuTmo) {return !xUaQEUSiDmj(VXGpnhctCInwcET(PjvRkpijDJvfyqjqyXyALgUBBIjCQsYTuTmo" ascii
    $s8  = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii
    $s9  = "function G(AxgLwoWPEarwLA,REetvhFKkILor,pYtUnhMpVUg) {AxgLwoWPEarwLA[REetvhFKkILor]=pYtUnhMpVUg;}" fullword ascii
    $s10 = "function vFFpFjDLPdRmYOJPSeRJLpNYZvogjZIPzmZjNFtvMcpSzsnkKDBoWc(vbFwRitaxuWGS,RNVxHpMdVTMKfI){ return EbOtHSo[QloQUOdE[aUbgv(vbF" ascii
    $s11 = "function xUaQEUSiDmj(zgCKqgUWCsUICs) {return isNaN(zgCKqgUWCsUICs);}" fullword ascii
    $s12 = "function JzZEvRapqoHj(aEnAOgFgzuPNk) {return isFinite(aEnAOgFgzuPNk);}" fullword ascii
    $s13 = "U);return aQSCg;}" fullword ascii
    $s14 = "function k(lyWjDiEEsSIZ,CSXCKqFUeWgFGS){lyWjDiEEsSIZ.push(CSXCKqFUeWgFGS);}" fullword ascii
    $s15 = "function aUbgv(bAZvlNPtDDZ,ZmOcKhnEKnZTW,ETpwHNaU){IWgx=QisnLAkcELPwlcjoF(bAZvlNPtDDZ,ZmOcKhnEKnZTW);aQSCg=IWgx.toString(ETpwHNa" ascii
    $s16 = "function vFFpFjDLPdRmYOJPSeRJLpNYZvogjZIPzmZjNFtvMcpSzsnkKDBoWc(vbFwRitaxuWGS,RNVxHpMdVTMKfI){ return EbOtHSo[QloQUOdE[aUbgv(vbF" ascii
    $s17 = "function jfIUiMkcCHpFbfy(fYFPnLBxbDXxfqVqQ,AzNXbQVuyVTKqVQBfaweokFciHBAfgwTUw,FDajtuzbfWhWXyRFwnEKvKJmelAMOpUxKUA){eval(fYFPnLBx" ascii
    $s18 = "function jfIUiMkcCHpFbfy(fYFPnLBxbDXxfqVqQ,AzNXbQVuyVTKqVQBfaweokFciHBAfgwTUw,FDajtuzbfWhWXyRFwnEKvKJmelAMOpUxKUA){eval(fYFPnLBx" ascii
    $s19 = "function aUbgv(bAZvlNPtDDZ,ZmOcKhnEKnZTW,ETpwHNaU){IWgx=QisnLAkcELPwlcjoF(bAZvlNPtDDZ,ZmOcKhnEKnZTW);aQSCg=IWgx.toString(ETpwHNa" ascii
    $s20 = "var t = new Array();t[0]=[];t[0][0]='d';t[0][1]='a';t[0][2]='d';t[0][3]='a';t[0][4]='46';t[0][5]='3d';t[0][6]='42';t[0][7]='14';" ascii

  condition:
    uint16(0) == 0x6c51 and
    8 of them
}