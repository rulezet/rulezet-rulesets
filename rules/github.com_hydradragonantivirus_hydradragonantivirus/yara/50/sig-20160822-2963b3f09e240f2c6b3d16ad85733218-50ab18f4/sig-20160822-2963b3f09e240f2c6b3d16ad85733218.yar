rule sig_20160822_2963b3f09e240f2c6b3d16ad85733218 {
  meta:
    description = "datamaliciousorder - file 20160822_2963b3f09e240f2c6b3d16ad85733218.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b47474c6f1714a541ec01d69b939e815792237ff4dabebf19ae4efbaf54e4213"

  strings:
    $s1 = "var UGc3 = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}