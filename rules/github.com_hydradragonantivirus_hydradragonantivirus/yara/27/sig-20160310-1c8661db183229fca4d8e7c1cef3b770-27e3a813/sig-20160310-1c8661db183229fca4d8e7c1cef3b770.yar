rule sig_20160310_1c8661db183229fca4d8e7c1cef3b770 {
  meta:
    description = "datamaliciousorder - file 20160310_1c8661db183229fca4d8e7c1cef3b770.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83b52432f9e9aa865486cbcb16621d83cbb66f8fdfc2ea3dbd75b627473a6905"

  strings:
    $s1  = "return smXJipj[0] + smXJipj[2] + smXJipj[4] + \".F\" + smXJipj[7] + smXJipj[9] + smXJipj[12] + smXJipj[14];" fullword ascii
    $s2  = "var Xl = true  , Ygbo = PTb[7] + PTb[9] + PTb[11];" fullword ascii
    $s3  = "var PTb = (\"2.XMLHTTP fswjdes jnqPg XML ream St hTFwnkxW AD JMwfzqv O nqYr D\").split(\" \");" fullword ascii
    $s4  = "TQgFd.open(VkGoz,hRxnX,false);" fullword ascii
    $s5  = "qhx.CreateFolder(BOoL);" fullword ascii
    $s6  = "if(l>=W.length) {break;}" fullword ascii
    $s7  = "function twrGEUQY(PLJ) {" fullword ascii
    $s8  = "function wpXM(apPKH) {" fullword ascii
    $s9  = "function eLRrU(JJZKFD) {" fullword ascii
    $s10 = "function bGBXpZG(rJMg,YXrcq) {" fullword ascii
    $s11 = "function HOTS(oRmHM,vlwbK) {" fullword ascii
    $s12 = "function xyOE(TQgFd,hRxnX,VkGoz) {" fullword ascii
    $s13 = "return PLJ.size;" fullword ascii
    $s14 = "function VmBl(NOaxs,JazUb) {" fullword ascii
    $s15 = "function TGvsJCZxC(LFRCxbOOPdE) {" fullword ascii
    $s16 = "return rJMg.ExpandEnvironmentStrings(YXrcq);" fullword ascii
    $s17 = "function yyPCKOYsr(AHODM,VkTLs,UwlDA,ffXP) {" fullword ascii
    $s18 = "function Edfh(zZlyr) {" fullword ascii
    $s19 = "return pwYoZ.status;" fullword ascii
    $s20 = "return mmahMGc" fullword ascii

  condition:
    uint16(0) == 0x0a0d and
    8 of them
}