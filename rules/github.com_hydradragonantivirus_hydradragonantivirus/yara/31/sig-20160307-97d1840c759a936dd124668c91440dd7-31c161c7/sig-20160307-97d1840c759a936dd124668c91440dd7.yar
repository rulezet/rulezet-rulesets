rule sig_20160307_97d1840c759a936dd124668c91440dd7 {
  meta:
    description = "datamaliciousorder - file 20160307_97d1840c759a936dd124668c91440dd7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a3e2d13a63cc6349f8f7de02baf99a9badaebdb7337da8d07c7faa09fe6f72c"

  strings:
    $s1  = "var TU = true  , okBH = cxq[7] + cxq[9] + cxq[11];" fullword ascii
    $s2  = "return ZeByewU[0] + ZeByewU[2] + ZeByewU[4] + \".F\" + ZeByewU[7] + ZeByewU[9] + ZeByewU[12] + ZeByewU[14];" fullword ascii
    $s3  = "var cxq = (\"2.XMLHTTP SXuHzXN PLeoY XML ream St hvZtIphw AD mCtGCDg O hXBt D\").split(\" \");" fullword ascii
    $s4  = "HVXyf.open(lwEHM,ZqLaq,false);" fullword ascii
    $s5  = "var ZeByewU = \"Sc MJHlZbg r KjiiDfEjV ipting OCdeSBs Akk ile cnieiBvJTvUFkX System tV WmGIk Obj tGUSRt ect Cqxpjmq\".split(\" " ascii
    $s6  = "return CofMJ;" fullword ascii
    $s7  = "rHP = Y; break; " fullword ascii
    $s8  = "function sodc(OMhFk) {" fullword ascii
    $s9  = "function TVGnVkq(qQgz) {" fullword ascii
    $s10 = "function PsAe(eAdzy) {" fullword ascii
    $s11 = "function IqKLM(eBcrtX) {" fullword ascii
    $s12 = "function MAVb(FQRLZ) {" fullword ascii
    $s13 = "if (((new Date())>0,7833348888)) {" fullword ascii
    $s14 = "function sZSKeQDhD(qlZhV,CrZbW,HzgUt,zRbt) {" fullword ascii
    $s15 = "function VKyx(MCKmT,dVOFq) {" fullword ascii
    $s16 = "return new ActiveXObject(eBcrtX);" fullword ascii
    $s17 = "function jjlEGxHf() {" fullword ascii
    $s18 = "function jCxUiYMsZ(poCDsnMfOwT) {" fullword ascii
    $s19 = "if(Y>=J.length) {break;}" fullword ascii
    $s20 = "if (i >= ziNGS.length) {break;}" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}