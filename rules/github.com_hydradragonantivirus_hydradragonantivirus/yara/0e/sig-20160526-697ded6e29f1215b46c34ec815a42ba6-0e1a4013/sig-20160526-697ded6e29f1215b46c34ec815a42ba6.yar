rule sig_20160526_697ded6e29f1215b46c34ec815a42ba6 {
  meta:
    description = "datamaliciousorder - file 20160526_697ded6e29f1215b46c34ec815a42ba6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a07dc81815842507c29b6bd36442a5256a44e210e3be7763b0b3c232b6ca6a7"

  strings:
    $s1  = "Math.sin(255), 2) + Math.pow(Math.cos(255), 2) - 1))-236)) zykDmXg += M(sozCUOfPVUuFbIa);else if (AlzJXfDExVGUrcsB == (210 + Mat" ascii
    $s2  = "function NNtWMVsW(mWkHGMXUZtzCs) {var gmzsFnizEElJvJkXFboDFANl = tNysNoclimALazOlEyG.join(HaCCboeHol[0]);var sozCUOfPVUuFbIa, fR" ascii
    $s3  = "function aUIgvpmgPJXpN(QqSbIfDZxqYbZCrOsMiHjV,pUFeedcHVAW){return QqSbIfDZxqYbZCrOsMiHjV.charAt(pUFeedcHVAW);}" fullword ascii
    $s4  = "AlzJXfDExVGUrcsB = mVJyR(gmzsFnizEElJvJkXFboDFANl,aUIgvpmgPJXpN(mWkHGMXUZtzCs,PwXbWmJ++));uFBGbDXhbVzksDHq = InKso<< (351 + Math" ascii
    $s5  = "function mVJyR(CTLNWWixVaDEOvpTaPYPmGFx,wDYDnBGWDwakfCMulPtyKxK){return CTLNWWixVaDEOvpTaPYPmGFx.indexOf(wDYDnBGWDwakfCMulPtyKxK" ascii
    $s6  = "function NNtWMVsW(mWkHGMXUZtzCs) {var gmzsFnizEElJvJkXFboDFANl = tNysNoclimALazOlEyG.join(HaCCboeHol[0]);var sozCUOfPVUuFbIa, fR" ascii
    $s7  = "function mVJyR(CTLNWWixVaDEOvpTaPYPmGFx,wDYDnBGWDwakfCMulPtyKxK){return CTLNWWixVaDEOvpTaPYPmGFx.indexOf(wDYDnBGWDwakfCMulPtyKxK" ascii
    $s8  = "function PVFgPPmmWq(ZBzoY,sdHsXfXBqBsFNyeDwaz){return String.fromCharCode(ZBzoY,sdHsXfXBqBsFNyeDwaz);}" fullword ascii
    $s9  = "function M(gmuJzkkNfmyfgsgiYVv){return String.fromCharCode(gmuJzkkNfmyfgsgiYVv);}" fullword ascii
    $s10 = "function ZEZybQsnWjdS(WgbgmridLKkcqPKwRrM,ViekPTkooo,BYdraw){return String.fromCharCode(WgbgmridLKkcqPKwRrM,ViekPTkooo,BYdraw);}" ascii
    $s11 = "e);else zykDmXg += ZEZybQsnWjdS(sozCUOfPVUuFbIa, fRHEeFGgcbgne, yBbeiqwSypwA);} while (PwXbWmJ < mWkHGMXUZtzCs.length);return zy" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}