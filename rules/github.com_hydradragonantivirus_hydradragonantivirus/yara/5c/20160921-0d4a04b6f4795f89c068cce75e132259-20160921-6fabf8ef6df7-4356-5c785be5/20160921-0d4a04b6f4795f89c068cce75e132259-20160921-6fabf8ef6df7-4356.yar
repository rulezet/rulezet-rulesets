rule _20160921_0d4a04b6f4795f89c068cce75e132259_20160921_6fabf8ef6df7_4356 {
  meta:
    description = "datamaliciousorder - from files 20160921_0d4a04b6f4795f89c068cce75e132259.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js, 20160921_a210d5e93bf8b06dbd0a1b262abe210f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e80f63f8ef5a9b52f119cc58d120fd7d74784d15d23ddc339948cb92383c800c"
    hash2       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"
    hash3       = "681408ae198939a760d376554e62f86e9d1fe2306266ffaee496dc9eed4d0687"

  strings:
    $s1 = " \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s2 = "ck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\"" ascii
    $s3 = "\"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s4 = "rn \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s5 = "uck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}