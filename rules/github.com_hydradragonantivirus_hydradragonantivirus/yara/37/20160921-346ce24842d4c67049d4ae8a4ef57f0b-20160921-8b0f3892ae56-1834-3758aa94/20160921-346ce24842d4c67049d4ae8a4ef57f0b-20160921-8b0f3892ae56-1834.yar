rule _20160921_346ce24842d4c67049d4ae8a4ef57f0b_20160921_8b0f3892ae56_1834 {
  meta:
    description = "datamaliciousorder - from files 20160921_346ce24842d4c67049d4ae8a4ef57f0b.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "24cea6347b33f54d332a2f5000d3f2841a3a09a1270f4da0da530495cac7ac0e"
    hash2       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"

  strings:
    $s1  = "n f000(){return \"NYh\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2  = "tion f000(){return \"KXg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"MBb\";})(),(function f000(){retur" ascii
    $s3  = "){return \"MDb\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})" ascii
    $s4  = "n \"Qa\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Nv\";})(),(fun" ascii
    $s5  = "GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Qa\";})(),(functio" ascii
    $s6  = "n f000(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"M" ascii
    $s7  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"DYx\";})(),(function f00" ascii
    $s8  = "on f000(){return \"Sv\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s9  = "ion f000(){return \"PTi\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s10 = "00(){return \"UEg\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}