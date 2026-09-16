rule sig_20151209_4a8d173fb086c34d0daf35e31d52193d {
  meta:
    description = "datamaliciousorder - file 20151209_4a8d173fb086c34d0daf35e31d52193d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08bcb3964e13c7a7ccf9ad5df9b03da8de495920c3271fd1e9eaccd795ecd56a"

  strings:
    $s1  = "function AbAYsZJ(NpbJrNwxqAYpwrznsZLfFQlUhrnKqKQLuVMb) {return !isNaN(parseFloat(NpbJrNwxqAYpwrznsZLfFQlUhrnKqKQLuVMb)) && isFin" ascii
    $s2  = "function AbAYsZJ(NpbJrNwxqAYpwrznsZLfFQlUhrnKqKQLuVMb) {return !isNaN(parseFloat(NpbJrNwxqAYpwrznsZLfFQlUhrnKqKQLuVMb)) && isFin" ascii
    $s3  = "function tslVQ(pYbfMSBtKEl,VLqGaXqdtKGOm,OTHnnlkJ){EguS=parseInt(pYbfMSBtKEl,VLqGaXqdtKGOm);dUTQE=EguS.toString(OTHnnlkJ);return" ascii
    $s4  = ";}} return ViRaPzWIXjT}" fullword ascii
    $s5  = "function SuwdHcvdXLpaWAsjs(BAdny){ViRaPzWIXjT= '';for(qZAvdXDuDkd=(-290+290)/398; qZAvdXDuDkd < (779+33)/406; qZAvdXDuDkd++) {xK" ascii
    $s6  = "function tslVQ(pYbfMSBtKEl,VLqGaXqdtKGOm,OTHnnlkJ){EguS=parseInt(pYbfMSBtKEl,VLqGaXqdtKGOm);dUTQE=EguS.toString(OTHnnlkJ);return" ascii
    $s7  = "function HWpNtTKevDxLmFDCCcvgUaGxEWVmabdATTIfxxCZrERYOieVkMSLWA(slbIEDRqSiJoP,YARKNXTcgbsvuI){ return CQlVT[tslVQ(slbIEDRqSiJoP[" ascii
    $s8  = "function HWpNtTKevDxLmFDCCcvgUaGxEWVmabdATTIfxxCZrERYOieVkMSLWA(slbIEDRqSiJoP,YARKNXTcgbsvuI){ return CQlVT[tslVQ(slbIEDRqSiJoP[" ascii
    $s9  = "function wLafrLwFErd(BDiodJrZ,zixbak){return BDiodJrZ.split(zixbak)}" fullword ascii
    $s10 = " dUTQE;}function cUEsGoXShAwJkfx(vFNpQmWrGmGsABiiW){eval(vFNpQmWrGmGsABiiW)}" fullword ascii
    $s11 = "function SuwdHcvdXLpaWAsjs(BAdny){ViRaPzWIXjT= '';for(qZAvdXDuDkd=(-290+290)/398; qZAvdXDuDkd < (779+33)/406; qZAvdXDuDkd++) {xK" ascii
    $s12 = "ohMeDkQ[qZAvdXDuDkd]=(-747+747)/727; while(true) { if(xKohMeDkQ[qZAvdXDuDkd] > BAdny[qZAvdXDuDkd].length-(107+534)/641) { break;" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}