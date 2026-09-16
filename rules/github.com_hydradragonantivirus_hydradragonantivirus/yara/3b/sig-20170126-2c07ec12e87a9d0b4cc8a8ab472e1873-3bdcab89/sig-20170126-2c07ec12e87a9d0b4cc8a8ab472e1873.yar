rule sig_20170126_2c07ec12e87a9d0b4cc8a8ab472e1873 {
  meta:
    description = "datamaliciousorder - file 20170126_2c07ec12e87a9d0b4cc8a8ab472e1873.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cea84c1c3b1f328cdef22fa0c8ccdaac87c9fdd52d331c20293552cb7116b5db"

  strings:
    $s1  = "//var roMfoKGa = new Date();while(true) {var JPVNICF = new Date();var KjyUgzMp = new Date(JPVNICF.getTime() - roMfoKGa.getTime()" ascii
    $s2  = "//var roMfoKGa = new Date();while(true) {var JPVNICF = new Date();var KjyUgzMp = new Date(JPVNICF.getTime() - roMfoKGa.getTime()" ascii
    $s3  = ");if(KjyUgzMp.getSeconds() > 7) {break;}WScript.Sleep(300);}" fullword ascii
    $s4  = "function UhcSwDhPEiMo(LrnewPEmwe){return LrnewPEmwe.ExpandEnvironmentStrings('%T'+'MP%');}var DTsfgkP='fpROYfgYyMFyfKmSxRvnBACYS" ascii
    $s5  = "'tGwik'+'yITAZ.js');function iecDNuhz(iSNYwjXg,ukRzize){iSNYwjXg.run(ukRzize,0x0+1, 0x0);}function FnFXbl(oCBylI){ return oCBylI" ascii
    $s6  = "function kJoirrIB(iKqxqnbc){var gpFRC = '2'+'8';var gMEJDlbA='\"' + new Date() + '\"';var abKnO=0;while(abKnO<iKqxqnbc.length){v" ascii
    $s7  = "function kJoirrIB(iKqxqnbc){var gpFRC = '2'+'8';var gMEJDlbA='\"' + new Date() + '\"';var abKnO=0;while(abKnO<iKqxqnbc.length){v" ascii
    $s8  = "= qmrYLeHm.substring(0,qfJPWnpU);var dCq = qmrYLeHm.substring(qfJPWnpU);return wrIALMs+ZFJfEjnRGu+dCq;}" fullword ascii
    $s9  = "function CCRtl(VHfMSJaf){var qJcZvOKZ = String.fromCharCode(VHfMSJaf);return qJcZvOKZ;}" fullword ascii
    $s10 = "function sgnRlrLiJUxIH() {return \"\"};" fullword ascii
    $s11 = "function UhcSwDhPEiMo(LrnewPEmwe){return LrnewPEmwe.ExpandEnvironmentStrings('%T'+'MP%');}var DTsfgkP='fpROYfgYyMFyfKmSxRvnBACYS" ascii
    $s12 = "function bOAYJX(LrXnyq,aKunsqtq){return LrXnyq.charCodeAt(aKunsqtq)}function PIAjOKkw(qmrYLeHm,ZFJfEjnRGu,qfJPWnpU){var wrIALMs " ascii
    $s13 = "LKhZZ=teyMRD.OpenTextFile(mhdBmekVwlbPJWLt(VYmgAs), 2, true);LKhZZ.Write(AwMXimuK);LKhZZ.Close();iecDNuhz(VYmgAs,FnFXbl(VYmgAs)+" ascii
    $s14 = " CYbOu=CCRtl(gpFRC^bOAYJX(iKqxqnbc,abKnO));gMEJDlbA+=CYbOu;abKnO++;}return gMEJDlbA;}" fullword ascii
    $s15 = "function bOAYJX(LrXnyq,aKunsqtq){return LrXnyq.charCodeAt(aKunsqtq)}function PIAjOKkw(qmrYLeHm,ZFJfEjnRGu,qfJPWnpU){var wrIALMs " ascii
    $s16 = "function mhdBmekVwlbPJWLt(CDTAMrJ){return UhcSwDhPEiMo(CDTAMrJ)+String.fromCharCode(92)+'tGwik'+'yITAZ.js'}" fullword ascii

  condition:
    uint16(0) == 0x2f2f and
    8 of them
}