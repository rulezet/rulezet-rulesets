rule TTP_XOR_QUAD_CurrentVersionRun_f9d4 {
  strings:
    $key_f9d4 = { aa bb [2] 8e b5 [2] a5 99 [2] 8b bb [2] 9f a0 [2] 90 ba [2] 8e a7 [2] 8c a6 [2] 97 a0 [2] 8b a7 [2] 97 88 }

  condition:
    any of them
}