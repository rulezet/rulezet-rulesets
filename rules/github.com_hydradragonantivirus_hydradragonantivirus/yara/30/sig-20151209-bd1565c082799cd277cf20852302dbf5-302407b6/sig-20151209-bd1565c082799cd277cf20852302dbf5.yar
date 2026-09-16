rule sig_20151209_bd1565c082799cd277cf20852302dbf5 {
  meta:
    description = "datamaliciousorder - file 20151209_bd1565c082799cd277cf20852302dbf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4693019254c734ed9b449eaf7411dadd873cc30df69117d8cfbc39bc53d1c734"

  strings:
    $s1  = "function SRwACoA(ahBwLxphDfCmevDFUvmztHvXrtbdIfdztLAS) {return !isNaN(parseFloat(ahBwLxphDfCmevDFUvmztHvXrtbdIfdztLAS)) && isFin" ascii
    $s2  = "function SRwACoA(ahBwLxphDfCmevDFUvmztHvXrtbdIfdztLAS) {return !isNaN(parseFloat(ahBwLxphDfCmevDFUvmztHvXrtbdIfdztLAS)) && isFin" ascii
    $s3  = "function ffGqFubuQYpSMVQfrRAWoUYFxepaTpaOiBYIclVNiLpUbRRmCWYmAZ(RKzUBMQbOeoKG,bDohoVVhlGnFey){ return IFMNa[avgdZ(RKzUBMQbOeoKG[" ascii
    $s4  = "+;}} return YpicwFaMhoV}" fullword ascii
    $s5  = "function RaDFcXRRBlIAgVvkf(vWxDY){YpicwFaMhoV= '';for(BkHiJtBdSvD=(-282+282)/14; BkHiJtBdSvD < (1010+414)/712; BkHiJtBdSvD++) {G" ascii
    $s6  = "function RaDFcXRRBlIAgVvkf(vWxDY){YpicwFaMhoV= '';for(BkHiJtBdSvD=(-282+282)/14; BkHiJtBdSvD < (1010+414)/712; BkHiJtBdSvD++) {G" ascii
    $s7  = "function ffGqFubuQYpSMVQfrRAWoUYFxepaTpaOiBYIclVNiLpUbRRmCWYmAZ(RKzUBMQbOeoKG,bDohoVVhlGnFey){ return IFMNa[avgdZ(RKzUBMQbOeoKG[" ascii
    $s8  = " vxRZu;}function FhXbNrDqtZiOxOH(SJvijhzommkdzSmhZ){eval(SJvijhzommkdzSmhZ)}" fullword ascii
    $s9  = "function avgdZ(WHCncHmmbrL,NTrvOrIQVsrfP,VxNhYAuw){xydK=parseInt(WHCncHmmbrL,NTrvOrIQVsrfP);vxRZu=xydK.toString(VxNhYAuw);return" ascii
    $s10 = "yesGQhJZ[BkHiJtBdSvD]=(-246+246)/681; while(true) { if(GyesGQhJZ[BkHiJtBdSvD] > vWxDY[BkHiJtBdSvD].length-(295+673)/968) { break" ascii
    $s11 = "function avgdZ(WHCncHmmbrL,NTrvOrIQVsrfP,VxNhYAuw){xydK=parseInt(WHCncHmmbrL,NTrvOrIQVsrfP);vxRZu=xydK.toString(VxNhYAuw);return" ascii
    $s12 = "function JrthHIKQhqF(TAOWZQrq,RnzocA){return TAOWZQrq.split(RnzocA)}" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}