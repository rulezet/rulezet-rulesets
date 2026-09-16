rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_8ed14dc63f5b_5200 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_8ed14dc63f5bac37baa70510a94f2915.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "e01d4cea60f1c16b2fc3a28a98b5ad4d421b0c4e8e5f757805e98a1436a9fadd"

  strings:
    $s1 = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(" ascii
    $s2 = "DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s3 = "ction f000(){return \"NYh\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Br\";})(),(function f000(){retur" ascii
    $s4 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sj\";})(),(function f00" ascii
    $s5 = "n f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"M" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}