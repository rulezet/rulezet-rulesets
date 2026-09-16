rule _20160921_d7492227e681b1689bfc5442a91a169e_20160921_dd666c66b3f1_5709 {
  meta:
    description = "datamaliciousorder - from files 20160921_d7492227e681b1689bfc5442a91a169e.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63aa129680edf69c72e8f077be5e8562f041fa0b0c7e63a8a9b219c23749b135"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = " \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s2 = " \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(fun" ascii
    $s3 = "ction f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return" ascii
    $s4 = "on f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"" ascii
    $s5 = "00(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}