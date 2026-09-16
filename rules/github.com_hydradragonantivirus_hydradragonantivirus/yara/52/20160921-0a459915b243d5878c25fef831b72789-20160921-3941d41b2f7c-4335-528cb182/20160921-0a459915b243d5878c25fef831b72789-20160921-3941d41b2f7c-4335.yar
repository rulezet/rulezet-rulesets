rule _20160921_0a459915b243d5878c25fef831b72789_20160921_3941d41b2f7c_4335 {
  meta:
    description = "datamaliciousorder - from files 20160921_0a459915b243d5878c25fef831b72789.js, 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f8d1944044e8a67a527f50e4aeb45e9358929b0d0f7aaf1730d2782f07a09de"
    hash2       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"

  strings:
    $s1 = "n \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s2 = " f000(){return \"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"D" ascii
    $s3 = " \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s4 = "\"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s5 = "),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Lp\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}