rule _20160921_35e8549205da39aa60fea8ac643ade8b_20160921_3941d41b2f7c_4902 {
  meta:
    description = "datamaliciousorder - from files 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_3941d41b2f7cb84a9ce802558f71cf2e.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash2       = "af803579fff33b5e316911dc121155eb553434eec287816287bbd86b427b3f7f"
    hash3       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash4       = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash5       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash6       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash7       = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash8       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash9       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"
    hash10      = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = " \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s2 = "0(){return \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";" ascii
    $s3 = "j\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function" ascii
    $s4 = "0(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\"" ascii
    $s5 = "ction f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}