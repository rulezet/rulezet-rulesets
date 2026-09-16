rule _20160921_02b826231ece268e91633311d2c70554_20160921_2746dcb02909_4137 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"

  strings:
    $s1 = "function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"MBb\";})(),(function f000(){r" ascii
    $s2 = "\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(function" ascii
    $s3 = "),(function f000(){return \"Vj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Wy\";})(),(function f000(){" ascii
    $s4 = "\"NBs\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s5 = "00(){return \"Yv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}