rule _20160921_220036ca1d4152e6bd72a833a4b3f832_20160921_2746dcb02909_1681 {
  meta:
    description = "datamaliciousorder - from files 20160921_220036ca1d4152e6bd72a833a4b3f832.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54f3e02c5b6d4d5d2db9a8d86252256d2f355ce582a09c9d870f84a9047c47ff"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"

  strings:
    $s1  = "{return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})" ascii
    $s2  = "0(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";" ascii
    $s3  = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s4  = "eturn \"Do\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s5  = ",(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000()" ascii
    $s6  = "){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";}" ascii
    $s7  = "on f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s8  = " f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s9  = "00(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl" ascii
    $s10 = "return \"ZFe\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})" ascii
    $s11 = ";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qa\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}