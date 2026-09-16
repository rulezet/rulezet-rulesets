rule sig_20151209_fda6a553dc3c29516d4699bd51af8680 {
  meta:
    description = "datamaliciousorder - file 20151209_fda6a553dc3c29516d4699bd51af8680.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bf1ce75cf65c20c08df40a53df39859c8afd349901398c8cfd38493de6c8f97"

  strings:
    $s1  = "function hzCdB(BKjTIxSlMXL,XljkJgHbQRunV,RfIErvBc){Kywr=parseInt(BKjTIxSlMXL,XljkJgHbQRunV);QTyyR=Kywr.toString(RfIErvBc);return" ascii
    $s2  = "function hzCdB(BKjTIxSlMXL,XljkJgHbQRunV,RfIErvBc){Kywr=parseInt(BKjTIxSlMXL,XljkJgHbQRunV);QTyyR=Kywr.toString(RfIErvBc);return" ascii
    $s3  = ";}} return pkXNYLaIpUR}" fullword ascii
    $s4  = "function qYtguUPqMZJ(IjvdpIza,IoljOq){return IjvdpIza.split(IoljOq)}" fullword ascii
    $s5  = " QTyyR;}function BsRyLuHqAFdzsKH(IpdCsLEqNHipelzKX){eval(IpdCsLEqNHipelzKX)}" fullword ascii
    $s6  = "function OOJglTXoIYRvCxYhK(XpSqU){pkXNYLaIpUR= '';for(pMkIWtATadE=(-921+921)/730; pMkIWtATadE < (-20+746)/363; pMkIWtATadE++) {x" ascii
    $s7  = "xXFeVJWl[pMkIWtATadE]=(-65+65)/870; while(true) { if(xxXFeVJWl[pMkIWtATadE] > XpSqU[pMkIWtATadE].length-(-143+982)/839) { break;" ascii
    $s8  = "function kGiTMyc(XIxomYoYTIbKTrfpCaHiEeWGLzyWyTsNSltb) {return !isNaN(parseFloat(XIxomYoYTIbKTrfpCaHiEeWGLzyWyTsNSltb)) && isFin" ascii
    $s9  = "function kGiTMyc(XIxomYoYTIbKTrfpCaHiEeWGLzyWyTsNSltb) {return !isNaN(parseFloat(XIxomYoYTIbKTrfpCaHiEeWGLzyWyTsNSltb)) && isFin" ascii
    $s10 = "function OOJglTXoIYRvCxYhK(XpSqU){pkXNYLaIpUR= '';for(pMkIWtATadE=(-921+921)/730; pMkIWtATadE < (-20+746)/363; pMkIWtATadE++) {x" ascii
    $s11 = "function psfXrOJQhgukzRCIEMyjciCcPtarFQGijcaifkOWDvvyqRmBODBcbW(IGvXCMQDcqhCh,VicWJgNElyPoDN){ return jDnZk[hzCdB(IGvXCMQDcqhCh[" ascii
    $s12 = "function psfXrOJQhgukzRCIEMyjciCcPtarFQGijcaifkOWDvvyqRmBODBcbW(IGvXCMQDcqhCh,VicWJgNElyPoDN){ return jDnZk[hzCdB(IGvXCMQDcqhCh[" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}