rule _20160921_2746dcb029094ed409681059b0bf7b68_20160921_582a5b9e6263_4761 {
  meta:
    description = "datamaliciousorder - from files 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash2       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash3       = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"

  strings:
    $s1 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(" ascii
    $s2 = " f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Z" ascii
    $s3 = "rn \"Ot\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(fu" ascii
    $s4 = "tion f000(){return \"QDg\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh\";})(),(function f000(){return " ascii
    $s5 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"MJq\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}