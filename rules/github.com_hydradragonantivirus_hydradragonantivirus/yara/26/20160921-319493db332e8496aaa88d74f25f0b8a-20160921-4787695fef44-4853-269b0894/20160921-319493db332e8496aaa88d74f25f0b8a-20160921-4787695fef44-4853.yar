rule _20160921_319493db332e8496aaa88d74f25f0b8a_20160921_4787695fef44_4853 {
  meta:
    description = "datamaliciousorder - from files 20160921_319493db332e8496aaa88d74f25f0b8a.js, 20160921_4787695fef4453a16be881bbe0f96c1a.js, 20160921_9d32b55f93b83e117524c4df15361eee.js, 20160921_dd28b3b2e4fae279f1dc4ba30acafda9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a0c9f735bec8627a5cf19b6426c972080cd36752f67aea5abb70a9217297a2e1"
    hash2       = "6a11e3d64ee2711e84433d2b8035ce0dafbcffa760c2026e3cfe9ba310008f90"
    hash3       = "3fe6572823305aa2316dd2ce562c85b9f6eb40f26ee354b5e0ff97b66cffd652"
    hash4       = "841abb0789337235f3a5367c6d4aa3806741a639f1faf0d54e41f125ecc1be02"

  strings:
    $s1 = "ion f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qz\"" ascii
    $s3 = "nction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){retu" ascii
    $s4 = "p\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qj\";})(),(function " ascii
    $s5 = "unction f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}