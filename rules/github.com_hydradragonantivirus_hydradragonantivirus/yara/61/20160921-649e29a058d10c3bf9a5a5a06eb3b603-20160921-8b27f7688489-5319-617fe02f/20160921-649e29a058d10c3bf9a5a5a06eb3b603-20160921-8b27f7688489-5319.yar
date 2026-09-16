rule _20160921_649e29a058d10c3bf9a5a5a06eb3b603_20160921_8b27f7688489_5319 {
  meta:
    description = "datamaliciousorder - from files 20160921_649e29a058d10c3bf9a5a5a06eb3b603.js, 20160921_8b27f7688489936aa1cc7fded52f4a64.js, 20160921_d57bd7101328f2bbf1f061a7dab83490.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6565dca0eb9e0e467a96242f29a80c650cc40a8892572ce8c28bfd197ace7fd0"
    hash2       = "dbf2fa1deb81fd17a55e884848d77b2d3c5d766fed0005f738840703aa8a9dda"
    hash3       = "fa72df41c05c5483fee755296c5d2da37c5e14a015c2aac82e7d9ad428cc2376"

  strings:
    $s1 = "eturn \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s2 = "\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vj\";})(),(function f" ascii
    $s3 = "(function f000(){return \"Go\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s4 = "WIj\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s5 = " \"OUx\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"BMj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}