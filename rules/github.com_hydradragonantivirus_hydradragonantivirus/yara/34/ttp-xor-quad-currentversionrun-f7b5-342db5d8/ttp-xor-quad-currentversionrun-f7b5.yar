rule TTP_XOR_QUAD_CurrentVersionRun_f7b5 {
  strings:
    $key_f7b5 = { a4 da [2] 80 d4 [2] ab f8 [2] 85 da [2] 91 c1 [2] 9e db [2] 80 c6 [2] 82 c7 [2] 99 c1 [2] 85 c6 [2] 99 e9 }

  condition:
    any of them
}