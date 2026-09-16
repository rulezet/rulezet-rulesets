rule _20160921_5541f4e80ad2d4f163ebcd0e8c899e59_20160921_80e6ac924bf1_3793 {
  meta:
    description = "datamaliciousorder - from files 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"

  strings:
    $s1 = "n\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Tn\";})(),(function f" ascii
    $s2 = "ion f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return" ascii
    $s3 = "unction f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function f000(){retu" ascii
    $s4 = "nction f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(function f000(){retur" ascii
    $s5 = "tion f000(){return \"Fs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s6 = ";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}