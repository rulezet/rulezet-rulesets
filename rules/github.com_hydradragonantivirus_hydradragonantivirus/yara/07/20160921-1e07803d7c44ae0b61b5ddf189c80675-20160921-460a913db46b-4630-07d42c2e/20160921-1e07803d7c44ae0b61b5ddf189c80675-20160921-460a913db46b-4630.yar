rule _20160921_1e07803d7c44ae0b61b5ddf189c80675_20160921_460a913db46b_4630 {
  meta:
    description = "datamaliciousorder - from files 20160921_1e07803d7c44ae0b61b5ddf189c80675.js, 20160921_460a913db46b41c41035cc210ed5fba0.js, 20160921_7e2de7c26f136a1a958818752613cac3.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a50e95e48071d391fd7544518c3c0394e9cde9051c76cf311992966b7414cc8"
    hash2       = "99bd08fbf869b4c9520d81d5b17512d87856474b8cf260494d0c88a47e0d37c9"
    hash3       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"
    hash4       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"
    hash5       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1 = "tion fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s2 = "\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function " ascii
    $s3 = "){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vf\";})" ascii
    $s4 = "ck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";" ascii
    $s5 = "rn \"KVh\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}