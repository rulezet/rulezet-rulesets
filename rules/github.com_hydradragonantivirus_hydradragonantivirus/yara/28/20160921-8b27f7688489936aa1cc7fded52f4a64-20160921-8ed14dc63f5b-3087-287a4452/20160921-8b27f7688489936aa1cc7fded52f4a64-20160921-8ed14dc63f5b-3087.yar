rule _20160921_8b27f7688489936aa1cc7fded52f4a64_20160921_8ed14dc63f5b_3087 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "w\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"DNa\";})(),(functio" ascii
    $s2 = "){return \"PTs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";" ascii
    $s3 = "rn \"DNa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s4 = "on f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s5 = ")(),(function f000(){return \"PTs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000" ascii
    $s6 = "tion f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){retur" ascii
    $s7 = "f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"TR" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}