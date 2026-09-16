rule _20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1_20160921_e949fdc198fe_5605 {
  meta:
    description = "datamaliciousorder - from files 20160921_a39f22c0c39a7d5bb3c55dd00a36b5b1.js, 20160921_e949fdc198fee477717395093f5853e7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a56bdeaf1decad9c4fa4ee5ac7e377d80dfd12601d1317d02f12d9d9fb19646"
    hash2       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"

  strings:
    $s1 = "eturn \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})()," ascii
    $s2 = "(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qz\";}" ascii
    $s3 = "KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4 = "n f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"" ascii
    $s5 = "(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}