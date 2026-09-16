rule TTP_XOR_QUAD_CurrentVersionRun_32d5 {
  strings:
    $key_32d5 = { 61 ba [2] 45 b4 [2] 6e 98 [2] 40 ba [2] 54 a1 [2] 5b bb [2] 45 a6 [2] 47 a7 [2] 5c a1 [2] 40 a6 [2] 5c 89 }

  condition:
    any of them
}