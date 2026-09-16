rule sig_20151209_ae12a837575d62b6f0d1c0afaa0eece2 {
  meta:
    description = "datamaliciousorder - file 20151209_ae12a837575d62b6f0d1c0afaa0eece2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a461e15a18493ec948913275fab2d2d71ef693202f1189fee379305c956c0b6b"

  strings:
    $s1  = "function xTINiFJ(abLVzrTmfNQAMfHazIzKYwMhCMoBvDVMqHVH) {return !isNaN(parseFloat(abLVzrTmfNQAMfHazIzKYwMhCMoBvDVMqHVH)) && isFin" ascii
    $s2  = "function xTINiFJ(abLVzrTmfNQAMfHazIzKYwMhCMoBvDVMqHVH) {return !isNaN(parseFloat(abLVzrTmfNQAMfHazIzKYwMhCMoBvDVMqHVH)) && isFin" ascii
    $s3  = " rdqeH;}function cGdBENPmIEtXkGZ(sxnKETwErBIUabAPQ){eval(sxnKETwErBIUabAPQ)}" fullword ascii
    $s4  = "function sPeOfefVulMRlukTw(hZDwB){kotCtXwRYOT= '';for(RfpYVcRTNjt=(-367+367)/109; RfpYVcRTNjt < (784+438)/611; RfpYVcRTNjt++) {h" ascii
    $s5  = "function gORpxAwLPZXPJBypCDyRwdjmzDOBJrowRnJYcnXMfmXWZYjOKoSoJM(vxGWNkEQHdEDq,UnlvaXYhSMVjow){ return XsZFj[dCFiJ(vxGWNkEQHdEDq[" ascii
    $s6  = "function dCFiJ(kxQpslBtGDb,JHFbXdfcWJYzj,ZBrIbwrT){PzkY=parseInt(kxQpslBtGDb,JHFbXdfcWJYzj);rdqeH=PzkY.toString(ZBrIbwrT);return" ascii
    $s7  = "function dCFiJ(kxQpslBtGDb,JHFbXdfcWJYzj,ZBrIbwrT){PzkY=parseInt(kxQpslBtGDb,JHFbXdfcWJYzj);rdqeH=PzkY.toString(ZBrIbwrT);return" ascii
    $s8  = "}} return kotCtXwRYOT}" fullword ascii
    $s9  = "function sPeOfefVulMRlukTw(hZDwB){kotCtXwRYOT= '';for(RfpYVcRTNjt=(-367+367)/109; RfpYVcRTNjt < (784+438)/611; RfpYVcRTNjt++) {h" ascii
    $s10 = "function gORpxAwLPZXPJBypCDyRwdjmzDOBJrowRnJYcnXMfmXWZYjOKoSoJM(vxGWNkEQHdEDq,UnlvaXYhSMVjow){ return XsZFj[dCFiJ(vxGWNkEQHdEDq[" ascii
    $s11 = "function VLDBHxLkvCS(qoZoRqIk,BPGSGK){return qoZoRqIk.split(BPGSGK)}" fullword ascii
    $s12 = "MmGOUnBf[RfpYVcRTNjt]=(-34+34)/924; while(true) { if(hMmGOUnBf[RfpYVcRTNjt] > hZDwB[RfpYVcRTNjt].length-(-401+734)/333) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}