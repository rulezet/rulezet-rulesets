rule TTP_XOR_QUAD_CurrentVersionRun_fed4 {
  strings:
    $key_fed4 = { ad bb [2] 89 b5 [2] a2 99 [2] 8c bb [2] 98 a0 [2] 97 ba [2] 89 a7 [2] 8b a6 [2] 90 a0 [2] 8c a7 [2] 90 88 }

  condition:
    any of them
}