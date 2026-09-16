rule TTP_XOR_QUAD_CurrentVersionRun_c285 {
  strings:
    $key_c285 = { 91 ea [2] b5 e4 [2] 9e c8 [2] b0 ea [2] a4 f1 [2] ab eb [2] b5 f6 [2] b7 f7 [2] ac f1 [2] b0 f6 [2] ac d9 }

  condition:
    any of them
}