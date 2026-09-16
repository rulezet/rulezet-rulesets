rule TTP_XOR_QUAD_CurrentVersionRun_4499 {
  strings:
    $key_4499 = { 17 f6 [2] 33 f8 [2] 18 d4 [2] 36 f6 [2] 22 ed [2] 2d f7 [2] 33 ea [2] 31 eb [2] 2a ed [2] 36 ea [2] 2a c5 }

  condition:
    any of them
}