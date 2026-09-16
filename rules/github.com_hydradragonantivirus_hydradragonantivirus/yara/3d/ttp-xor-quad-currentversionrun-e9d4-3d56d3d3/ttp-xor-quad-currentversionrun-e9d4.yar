rule TTP_XOR_QUAD_CurrentVersionRun_e9d4 {
  strings:
    $key_e9d4 = { ba bb [2] 9e b5 [2] b5 99 [2] 9b bb [2] 8f a0 [2] 80 ba [2] 9e a7 [2] 9c a6 [2] 87 a0 [2] 9b a7 [2] 87 88 }

  condition:
    any of them
}