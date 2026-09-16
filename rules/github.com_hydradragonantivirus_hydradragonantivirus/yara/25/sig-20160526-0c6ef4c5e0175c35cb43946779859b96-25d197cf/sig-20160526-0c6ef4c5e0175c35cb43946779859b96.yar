rule sig_20160526_0c6ef4c5e0175c35cb43946779859b96 {
  meta:
    description = "datamaliciousorder - file 20160526_0c6ef4c5e0175c35cb43946779859b96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99c2b793cefd78acb1fa933cb5c141e4cb90d6e56eb2c3560d26dd601e2b1073"

  strings:
    $s1  = " lA(YIPQVXOuvdj);else if (JGTrsLwcQhOiKlnZkm == (278 + Math.round((Math.pow(Math.sin(14), 2) + Math.pow(Math.cos(14), 2) - 1))-2" ascii
    $s2  = "function GzEMgkUn(lhGdorujeRruD) {var xWTJLwkvFmpVGyIgwhNbnF = RrCNTriezxPoBruLdTUYYzY.join(VqqUiPGrGeSXxQKr[0]);var YIPQVXOuvdj" ascii
    $s3  = "function RZCuIvvEBgNEuA(HUSbLxedMEMEhDgKsnmoH,ELGywt){return HUSbLxedMEMEhDgKsnmoH.charAt(ELGywt);}" fullword ascii
    $s4  = "function GiXVEZEkmtyoHvdxIbbVE(vHUKpmiXlzGrEgGjXKfE,HErunuXTinwMFzPpfxG){return vHUKpmiXlzGrEgGjXKfE.indexOf(HErunuXTinwMFzPpfxG" ascii
    $s5  = "function GiXVEZEkmtyoHvdxIbbVE(vHUKpmiXlzGrEgGjXKfE,HErunuXTinwMFzPpfxG){return vHUKpmiXlzGrEgGjXKfE.indexOf(HErunuXTinwMFzPpfxG" ascii
    $s6  = "function GzEMgkUn(lhGdorujeRruD) {var xWTJLwkvFmpVGyIgwhNbnF = RrCNTriezxPoBruLdTUYYzY.join(VqqUiPGrGeSXxQKr[0]);var YIPQVXOuvdj" ascii
    $s7  = "NvokOOtMftThST);} while (ozInODLmKsIMOKpIyiXZY < lhGdorujeRruD.length);return NxLjwbuQJjLyR;}" fullword ascii
    $s8  = "function fmNPu(ercxsOVohsu,qneJe){return String.fromCharCode(ercxsOVohsu,qneJe);}" fullword ascii
    $s9  = "function lA(GskYAVWFAqQBMSgEV){return String.fromCharCode(GskYAVWFAqQBMSgEV);}" fullword ascii
    $s10 = "function caVSRqfZlmJpJVhVqY(pzoIXFOxWjBhs,JZUhZJDoKbbSHRBbBTza,xWjytOjqnuMFHxPKpUi){return String.fromCharCode(pzoIXFOxWjBhs,JZU" ascii
    $s11 = "14)) NxLjwbuQJjLyR += fmNPu(YIPQVXOuvdj, yBHJYAUynS);else NxLjwbuQJjLyR += caVSRqfZlmJpJVhVqY(YIPQVXOuvdj, yBHJYAUynS, qnCBvwWLw" ascii
    $s12 = "function caVSRqfZlmJpJVhVqY(pzoIXFOxWjBhs,JZUhZJDoKbbSHRBbBTza,xWjytOjqnuMFHxPKpUi){return String.fromCharCode(pzoIXFOxWjBhs,JZU" ascii

  condition:
    uint16(0) == 0x6176 and
    8 of them
}