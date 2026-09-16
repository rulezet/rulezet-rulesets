rule _20160921_10a3e0605b8ced0a0dee77069aa99014_20160921_13ded02861a1_4404 {
  meta:
    description = "datamaliciousorder - from files 20160921_10a3e0605b8ced0a0dee77069aa99014.js, 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_b4c84c92954782bcf19013150a359ec6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "462b92b513dfa104fe3c095cbf98c34389b13ed004671baf4f95430e8487a108"
    hash2       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash3       = "deac288c0b80bcd19eff4e9a4bb55e7bdc0f08b0110094a0693c671b47cda285"

  strings:
    $s1 = "00(){return \"Qj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";}" ascii
    $s2 = " f000(){return \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"R" ascii
    $s3 = "turn \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Mu\";})(),(" ascii
    $s4 = "turn \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s5 = "rn \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}