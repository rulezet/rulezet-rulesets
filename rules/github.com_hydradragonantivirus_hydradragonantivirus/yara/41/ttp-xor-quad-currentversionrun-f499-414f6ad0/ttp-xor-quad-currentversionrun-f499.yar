rule TTP_XOR_QUAD_CurrentVersionRun_f499 {
  strings:
    $key_f499 = { a7 f6 [2] 83 f8 [2] a8 d4 [2] 86 f6 [2] 92 ed [2] 9d f7 [2] 83 ea [2] 81 eb [2] 9a ed [2] 86 ea [2] 9a c5 }

  condition:
    any of them
}