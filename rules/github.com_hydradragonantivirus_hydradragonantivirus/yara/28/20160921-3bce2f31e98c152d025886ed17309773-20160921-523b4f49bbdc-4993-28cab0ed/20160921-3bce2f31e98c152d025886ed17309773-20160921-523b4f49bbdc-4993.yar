rule _20160921_3bce2f31e98c152d025886ed17309773_20160921_523b4f49bbdc_4993 {
  meta:
    description = "datamaliciousorder - from files 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_5f0fd6cffcc723799fdcc54a3c2a7ba5.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash2       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash3       = "f215df78f73f84c8424edec81b4a9e43c0b766f9010caf095301b900f03214fb"
    hash4       = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1 = "n f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s2 = "),(function f000(){return \"Qz\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000()" ascii
    $s3 = "on f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Z" ascii
    $s4 = "n f000(){return \"Lp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"K" ascii
    $s5 = "f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}