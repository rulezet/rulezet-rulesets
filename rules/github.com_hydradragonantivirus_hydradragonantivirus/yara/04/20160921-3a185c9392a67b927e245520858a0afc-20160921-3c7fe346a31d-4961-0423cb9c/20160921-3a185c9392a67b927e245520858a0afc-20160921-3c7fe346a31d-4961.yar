rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_3c7fe346a31d_4961 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_3c7fe346a31de0bd4c8d2ac0fc848e26.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_91d6a421bfd5ccdb59d33b75574567eb.js, 20160921_a056f27a8b6d780ba88209aaee1ebb68.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "9416bb519c790de32506a7f01be471201203ef899168387fe44a40151f0b662f"
    hash3       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash4       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash5       = "fcd86e83ff6948b25dbdbac7ed6b6c8d750729e1da24f7598ff0e0b575909d4b"
    hash6       = "314665ef3670769c41db6783cc9eb408dcbce4749a56c09166a1862331791bf3"
    hash7       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash8       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash9       = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1 = "IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s2 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";})(),(function f000(){" ascii
    $s3 = "ion f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(function f000(){return " ascii
    $s4 = "(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"IAa\";" ascii
    $s5 = "urn \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}