rule TTP_XOR_QUAD_CurrentVersionRun_29d4 {
  strings:
    $key_29d4 = { 7a bb [2] 5e b5 [2] 75 99 [2] 5b bb [2] 4f a0 [2] 40 ba [2] 5e a7 [2] 5c a6 [2] 47 a0 [2] 5b a7 [2] 47 88 }

  condition:
    any of them
}