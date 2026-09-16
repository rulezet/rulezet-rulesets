rule _20160921_9dad243650b7872772e7037b467b5a2e_20160921_dd666c66b3f1_5588 {
  meta:
    description = "datamaliciousorder - from files 20160921_9dad243650b7872772e7037b467b5a2e.js, 20160921_dd666c66b3f13d3a71b957c0e646c0a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0d6dd5e22f8f66e5240683d3b57744793a88315a385138ff11409b0c03a9c448"
    hash2       = "77e753e21a464bef9fad04f7d41ce8b192c797808ff1b22efe474c612c25f2b2"

  strings:
    $s1 = "\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s2 = "Kl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s3 = "(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";" ascii
    $s4 = "\"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(func" ascii
    $s5 = "0(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}