rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_5d6863feab41_4246 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_5d6863feab411af8217516a1b111aa40.js, 20160921_c79bcee11e764b4ca54b637f14f94e36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "0dbd74ce266dbd495fb6fc7810ec67099f628d975c524a9190f91ccc4bf433bb"
    hash3       = "fdd10a2dcebc0c4099b99fb3316b9cdd6c3afd60abc1b93345fc041eb2405ec0"

  strings:
    $s1 = "rn \"Oe\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s2 = "nction f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s3 = " f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy" ascii
    $s4 = "unction f000(){return \"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){ret" ascii
    $s5 = "function f000(){return \"GGn\";})(),(function f000(){return \"Ug\";})(),(function f000(){return \"WIj\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}