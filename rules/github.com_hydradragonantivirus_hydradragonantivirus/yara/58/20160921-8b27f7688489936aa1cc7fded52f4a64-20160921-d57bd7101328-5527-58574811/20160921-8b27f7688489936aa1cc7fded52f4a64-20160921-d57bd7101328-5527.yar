rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_d57bd7101328_5527 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js, 20160921_e985c90f8141417e484ad0056c9b809c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"
    hash3       = "513b80dc65238dcfcb80f0e8e4f456645bf345b2dde46805b001c07bc579d4c9"

  strings:
    $s1 = ",(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s2 = "000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TK" ascii
    $s3 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi" ascii
    $s4 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s5 = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}