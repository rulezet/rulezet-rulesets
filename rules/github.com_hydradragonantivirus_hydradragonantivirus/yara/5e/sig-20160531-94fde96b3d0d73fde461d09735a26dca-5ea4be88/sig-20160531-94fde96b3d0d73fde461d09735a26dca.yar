rule sig_20160531_94fde96b3d0d73fde461d09735a26dca {
  meta:
    description = "datamaliciousorder - file 20160531_94fde96b3d0d73fde461d09735a26dca.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9667781e7e614944233dec3cd80661490937854f0b624c9d03cfc2be12f9666a"

  strings:
    $s1  = "var kNOIhofW=function(){return WScript.CreateObject(jKdNXXJxwSKJGyTvNFfE[2].replace(new RegExp(\"u\",\"g\"),\"\"));}();" fullword ascii
    $s2  = "function WTmmqqTDSYn(XkPIELmL,cKjDziTqI){return XkPIELmL.charAt(cKjDziTqI);}" fullword ascii
    $s3  = "function mOktOr(){return kNOIhofW.ExpandEnvironmentStrings(qeUedCuv())}" fullword ascii
    $s4  = "var olVTHOtvJAVUV=function(){return new ActiveXObject(jKdNXXJxwSKJGyTvNFfE[1]);}();" fullword ascii
    $s5  = "function mZaUOvkwsRUsvSWjaTZ(fVTswj,CHkXwfehpwxJ,mGwptmycITQRQVgQ){return String.fromCharCode(fVTswj,CHkXwfehpwxJ,mGwptmycITQRQV" ascii
    $s6  = "function lAmClorFACBz(HRTzMqyXAOQX,cEDlyGhHrzDero) {var kYDDcU=[jKdNXXJxwSKJGyTvNFfE[15]];HRTzMqyXAOQX[kYDDcU[0]]" fullword ascii
    $s7  = "function J(IRZgTvWCekcZ){return String.fromCharCode(IRZgTvWCekcZ);}" fullword ascii
    $s8  = "function hkUCPv(WQnlZVKjgkDlC,xVAiZxK,OYkwbcC){wQNCPelWeO=WQnlZVKjgkDlC.split(OYkwbcC);UvmqjD = jKdNXXJxwSKJGyTvNFfE[0];for(LKdg" ascii
    $s9  = "(cEDlyGhHrzDero,0x1,0x0)}function YVnYnG(LerRUTvJ,xrIVOwDH,xZsBXPepDTrjMI){var TiUFBVSxx=LerRUTvJ.createtextfile(xrIVOwDH,true);" ascii
    $s10 = "function wRXrKsqw(KFpbVapSzkgDY) {var OaoCyFOzP = PDgWDsU.join(jKdNXXJxwSKJGyTvNFfE[7]);var yAfTq, rjlmnlGgREEppoqpQTgQB, aueGHm" ascii
    $s11 = "function JVMPOe(){return hkUCPv(jKdNXXJxwSKJGyTvNFfE[13],[0,3,6],jKdNXXJxwSKJGyTvNFfE[14]);}" fullword ascii
    $s12 = "H += aGOUYzFsfQoxVXSX(yAfTq, rjlmnlGgREEppoqpQTgQB);else aKwXMHQXjUqlKrYLkqPHKBH += mZaUOvkwsRUsvSWjaTZ(yAfTq, rjlmnlGgREEppoqpQ" ascii
    $s13 = "function aGOUYzFsfQoxVXSX(LQWSmBjpYwF,iauCoVQSDq){return String.fromCharCode(LQWSmBjpYwF,iauCoVQSDq);}" fullword ascii
    $s14 = "function hkUCPv(WQnlZVKjgkDlC,xVAiZxK,OYkwbcC){wQNCPelWeO=WQnlZVKjgkDlC.split(OYkwbcC);UvmqjD = jKdNXXJxwSKJGyTvNFfE[0];for(LKdg" ascii
    $s15 = "function sppfBMqMjsD(IYUdhEksZAIi,JkCkUCmfLgY){return IYUdhEksZAIi.indexOf(JkCkUCmfLgY);}" fullword ascii
    $s16 = "(cEDlyGhHrzDero,0x1,0x0)}function YVnYnG(LerRUTvJ,xrIVOwDH,xZsBXPepDTrjMI){var TiUFBVSxx=LerRUTvJ.createtextfile(xrIVOwDH,true);" ascii
    $s17 = "function qeUedCuv(){return hkUCPv(jKdNXXJxwSKJGyTvNFfE[9],[1,5,7],jKdNXXJxwSKJGyTvNFfE[10]);}" fullword ascii
    $s18 = "eR=0;LKdgeR<xVAiZxK.length;LKdgeR++) {UvmqjD+=wQNCPelWeO[xVAiZxK[LKdgeR]];}return UvmqjD.substring(3,UvmqjD.length);}" fullword ascii
    $s19 = "function mZaUOvkwsRUsvSWjaTZ(fVTswj,CHkXwfehpwxJ,mGwptmycITQRQVgQ){return String.fromCharCode(fVTswj,CHkXwfehpwxJ,mGwptmycITQRQV" ascii
    $s20 = "TgQB, aueGHmErAHBhcPUNhpHJ);} while (dhwgiDOIjOkRDlejtVsxoTC < KFpbVapSzkgDY.length);return aKwXMHQXjUqlKrYLkqPHKBH;}" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    8 of them
}