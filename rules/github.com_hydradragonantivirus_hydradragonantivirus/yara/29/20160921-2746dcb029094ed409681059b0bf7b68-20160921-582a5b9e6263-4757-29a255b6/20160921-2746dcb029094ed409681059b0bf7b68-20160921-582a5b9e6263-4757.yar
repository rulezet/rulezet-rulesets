rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_4757 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash4       = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash5       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "00(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";" ascii
    $s2 = "nction f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){retu" ascii
    $s3 = "return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})()" ascii
    $s4 = "rn \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(fun" ascii
    $s5 = ")(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}