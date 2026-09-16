rule TTP_XOR_QUAD_CurrentVersionRun_eed4 {
  strings:
    $key_eed4 = { bd bb [2] 99 b5 [2] b2 99 [2] 9c bb [2] 88 a0 [2] 87 ba [2] 99 a7 [2] 9b a6 [2] 80 a0 [2] 9c a7 [2] 80 88 }

  condition:
    any of them
}