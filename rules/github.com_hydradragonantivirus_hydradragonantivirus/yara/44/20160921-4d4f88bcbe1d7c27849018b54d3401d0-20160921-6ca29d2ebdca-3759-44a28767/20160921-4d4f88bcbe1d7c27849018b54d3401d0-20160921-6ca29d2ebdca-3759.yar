rule _20160921_4d4f88bcbe1d7c27849018b54d3401d0_20160921_6ca29d2ebdca_3759 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_6ca29d2ebdcaa2724b801c02414faf7f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash2       = "b810435d98ebab77ad9d2cd316e2a0c0211b0941d86cbfa6c0e753732c6d3b15"

  strings:
    $s1 = "BMj\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s2 = "{return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})" ascii
    $s3 = "eturn \"MJq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"PTi\";})()" ascii
    $s4 = "on f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s5 = "rn \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTs\";})(),(f" ascii
    $s6 = "rn \"ZIi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}