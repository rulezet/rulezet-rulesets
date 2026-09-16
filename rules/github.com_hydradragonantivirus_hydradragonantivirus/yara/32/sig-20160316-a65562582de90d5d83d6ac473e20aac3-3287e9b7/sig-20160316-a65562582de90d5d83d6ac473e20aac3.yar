rule sig_20160316_a65562582de90d5d83d6ac473e20aac3 {
  meta:
    description = "datamaliciousorder - file 20160316_a65562582de90d5d83d6ac473e20aac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c84fdfd9a74a77a84219d713efb7c89b80e77ecbcf74271203c400638bb777f"

  strings:
    $s1 = "while (WGvjwft[oZtCoBtwf + ARKAlW + WBjd + iPvwvHe + Zipzvm] < 4 ) {WScript[wfXmQqy + EDApggBHYufObxB](1000)};" fullword ascii
    $s2 = "UGdvuaeC + vbYGLftB + MAmzq + MTRfBlzVKJlsJoB + SvOfFeCLsFMT + wqySQcBugphSu + WVicHnS + mhXjdMEA + dXzh, false);" fullword ascii
    $s3 = "function NOGxydLY(n){return CrxFjFBPwsvGFf + WmkCpduvydFO + JMLRnJYi + JJmU + JuFamJ + hpERAQA;}" fullword ascii
    $s4 = "WGvjwft[VHbRbH + RlPRMFj](tEDKXBiBuqSqMF + XgfPeAEn, yCiPTCxcCR + GqoKFWw + yGafMjYtfOGytl + IKiKIkTbVu + vhtnnRE + RgxGF + kTuo" ascii
    $s5 = "function SyxbiKaIFKH(rVCJBSrkXUKYy){QLQbwTPatNWCG[BkOALKH](rVCJBSrkXUKYy, 0, 0);}" fullword ascii
    $s6 = "var FBTVSdHBU = new Date();" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}