rule TTP_XOR_QUAD_CurrentVersionRun_cd84 {
  strings:
    $key_cd84 = { 9e eb [2] ba e5 [2] 91 c9 [2] bf eb [2] ab f0 [2] a4 ea [2] ba f7 [2] b8 f6 [2] a3 f0 [2] bf f7 [2] a3 d8 }

  condition:
    any of them
}