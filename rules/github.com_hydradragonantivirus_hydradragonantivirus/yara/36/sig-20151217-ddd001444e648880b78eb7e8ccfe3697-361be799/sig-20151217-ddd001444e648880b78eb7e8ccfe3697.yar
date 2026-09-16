rule sig_20151217_ddd001444e648880b78eb7e8ccfe3697 {
  meta:
    description = "datamaliciousorder - file 20151217_ddd001444e648880b78eb7e8ccfe3697.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beb85ef09fd2ff63193915f9ebf60053c3f595b74f380c0e6de2851ff652b0a9"

  strings:
    $s1  = "pow(Math.cos(123), 2) - 1)));} MlOPaVmfK[cYsBmCmgJqt]++;}cYsBmCmgJqt++;} return tOXxrZXplGs}" fullword ascii
    $s2  = "th.pow(Math.cos(827), 2) - 1)); while(true) { if(MlOPaVmfK[cYsBmCmgJqt] > GsSYq[cYsBmCmgJqt].length-(-262+423)/161) { break; } i" ascii
    $s3  = ") - 1));while(true){if (cYsBmCmgJqt >= (2336+730)/511){break;}MlOPaVmfK[cYsBmCmgJqt]=Math.round((Math.pow(Math.sin(827), 2) + Ma" ascii
    $s4  = "function iDcvBZYQrylUPorjo(GsSYq){tOXxrZXplGs= '';cYsBmCmgJqt=Math.round((Math.pow(Math.sin(371), 2) + Math.pow(Math.cos(371), 2" ascii
    $s5  = "ZbytgXqbNOhNlnNgueJSPVrSsEKaqTFHFvt([GsSYq[cYsBmCmgJqt][MlOPaVmfK[cYsBmCmgJqt]]], Math.round((Math.pow(Math.sin(123), 2) + Math." ascii
    $s6  = "function iDcvBZYQrylUPorjo(GsSYq){tOXxrZXplGs= '';cYsBmCmgJqt=Math.round((Math.pow(Math.sin(371), 2) + Math.pow(Math.cos(371), 2" ascii
    $s7  = "function iBoVzpE(FwhcPEsBPPmiiQojEMCceVMqrBRsWSgFmCeK) {return !CfCkkLxGRBi(oUiDdsvyqYVDJol(FwhcPEsBPPmiiQojEMCceVMqrBRsWSgFmCeK" ascii
    $s8  = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s9  = "function eauNcJItIjpQ(zYmUjDXKMnAOS) {return isFinite(zYmUjDXKMnAOS);}" fullword ascii
    $s10 = "function oUiDdsvyqYVDJol(IRVRXYQDEPZBwssUeYz) {return parseFloat(IRVRXYQDEPZBwssUeYz);}" fullword ascii
    $s11 = "function oMbWOIAWaHXaMnP(ZlyWRzbCySnbjgYcm,cGParfPpILFCRmPVVxTQoTTcdjIgMgjkRe,syYooGvnRTQLKHldvxvJxUKGSlGpnlBJkwS){eval(ZlyWRzbC" ascii
    $s12 = "function oMbWOIAWaHXaMnP(ZlyWRzbCySnbjgYcm,cGParfPpILFCRmPVVxTQoTTcdjIgMgjkRe,syYooGvnRTQLKHldvxvJxUKGSlGpnlBJkwS){eval(ZlyWRzbC" ascii
    $s13 = "var X = new Array();X[0]=[];X[0][0]='d';X[0][1]='a';X[0][2]='d';X[0][3]='a';X[0][4]='46';X[0][5]='3d';X[0][6]='42';X[0][7]='14';" ascii
    $s14 = "q);return tMMZz;}" fullword ascii
    $s15 = "function g(UkIprIHQYufXoY,nTAfuUfRMwARV,YJzDMAeVUNC) {UkIprIHQYufXoY[nTAfuUfRMwARV]=YJzDMAeVUNC;}" fullword ascii
    $s16 = "function sfupvOAArMIhXYttZ(XyRfRystkl,nEXdgOqpCW) {return parseInt(XyRfRystkl,nEXdgOqpCW);}" fullword ascii
    $s17 = "function z(NhxMvPwAXNYX,VMRkOymWQSydfr){NhxMvPwAXNYX.push(VMRkOymWQSydfr);}" fullword ascii
    $s18 = "function CfCkkLxGRBi(qzxIgNzyPLSXzK) {return isNaN(qzxIgNzyPLSXzK);}" fullword ascii
    $s19 = "function iBoVzpE(FwhcPEsBPPmiiQojEMCceVMqrBRsWSgFmCeK) {return !CfCkkLxGRBi(oUiDdsvyqYVDJol(FwhcPEsBPPmiiQojEMCceVMqrBRsWSgFmCeK" ascii
    $s20 = "function BOCAk(rYcvazNYOpj,iwJeSPCblZZrl,BVXCboOq){cviS=sfupvOAArMIhXYttZ(rYcvazNYOpj,iwJeSPCblZZrl);tMMZz=cviS.toString(BVXCboO" ascii

  condition:
    uint16(0) == 0x7945 and
    8 of them
}