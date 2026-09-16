rule sig_20160323_709dff396a66523720e424f81c34a9e6 {
  meta:
    description = "datamaliciousorder - file 20160323_709dff396a66523720e424f81c34a9e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd821546a7089f29264d52f922fdd85f38701b3ad4c48944ba9dbbc23739cd70"

  strings:
    $s1  = "return WScript.CreateObject(FidTI);" fullword ascii
    $s2  = "var GP = true  , rJcB = AxX[7] + AxX[9] + AxX[11];" fullword ascii
    $s3  = "return euQPNEa[0] + euQPNEa[2] + euQPNEa[4] + \".F\" + euQPNEa[7] + euQPNEa[9] + euQPNEa[12] + euQPNEa[14];" fullword ascii
    $s4  = "VpmP.open(HuQkH,gRHMv,false);" fullword ascii
    $s5  = "var AxX = (\"2.XMLHTTP eWjaDaZ KqUjE XML ream St BfGaAmEY AD XMgYpSX O GoaR D\").split(\" \");" fullword ascii
    $s6  = "var euQPNEa = ZtJye(xombajuXfF+\" \"+\"System Gi KAAaq Obj tvDnAX ect TkUyCVi Renax\", \" \");" fullword ascii
    $s7  = "function asMT(FidTI) {" fullword ascii
    $s8  = "function IDlz(wzHIr) {" fullword ascii
    $s9  = "function AtkO(lIHCH) {" fullword ascii
    $s10 = "function hJNU(IGYtX,gRHMv,HuQkH) {" fullword ascii
    $s11 = "function kmhe(vwQrY,suXbE) {" fullword ascii
    $s12 = "function dsyu(sggWl,xsAXQ) {" fullword ascii
    $s13 = "return QFzMI.status;" fullword ascii
    $s14 = "return AxWr.ExpandEnvironmentStrings(mSslT);" fullword ascii
    $s15 = "function wLIWc(KPFBrS) {" fullword ascii
    $s16 = "function AjVBIDR(AYcu) {" fullword ascii
    $s17 = "return vpy.split(DCcSb);" fullword ascii
    $s18 = "if(N>=K.length) {break;}" fullword ascii
    $s19 = "return new ActiveXObject(OZee);" fullword ascii
    $s20 = "function sptMvALL(foJ) {" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}