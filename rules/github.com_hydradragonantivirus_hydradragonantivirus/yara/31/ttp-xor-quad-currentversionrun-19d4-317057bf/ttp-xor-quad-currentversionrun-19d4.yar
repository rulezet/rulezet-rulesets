rule TTP_XOR_QUAD_CurrentVersionRun_19d4 {
  strings:
    $key_19d4 = { 4a bb [2] 6e b5 [2] 45 99 [2] 6b bb [2] 7f a0 [2] 70 ba [2] 6e a7 [2] 6c a6 [2] 77 a0 [2] 6b a7 [2] 77 88 }

  condition:
    any of them
}