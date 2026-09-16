rule sig_20160315_dab159e4ad0ac32c6f64858e5429724f {
  meta:
    description = "datamaliciousorder - file 20160315_dab159e4ad0ac32c6f64858e5429724f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d70d81c72aead200c574959e6640d273565edf97eaa02c14b693e16e6f03b8b8"

  strings:
    $s1 = "function yksXYTm(Ked){WshShell[Smb + xnrBhzgVekLqddy](Ked, 0, 0);}" fullword ascii
    $s2 = "while (MVmqAmrSnXy.readystate < 4 ) {WScript.Sleep(1000)};" fullword ascii
    $s3 = "function SxaPuBwiIxz(n){return GFrlNjPKZOGX + loQFWGvUqnCx + flpKWBNnjhqlA + IhSaRHSa + gPlckmBuvl + rEt + uezbVr;}" fullword ascii
    $s4 = "var xtfhdKCOqyDSiL = new Date();" fullword ascii
    $s5 = "MVmqAmrSnXy[qvJvuIYDJ + cqybkhXUaNq](noOtzq, fNVXklUbOBWQcan + VMj + YVHIIGXHALsxZ + QmZmLQo + VqHfOHQK + esdtAWpScXmu + Nvxfhfh" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}