rule TTP_XOR_QUAD_CurrentVersionRun_32d7 {
  strings:
    $key_32d7 = { 61 b8 [2] 45 b6 [2] 6e 9a [2] 40 b8 [2] 54 a3 [2] 5b b9 [2] 45 a4 [2] 47 a5 [2] 5c a3 [2] 40 a4 [2] 5c 8b }

  condition:
    any of them
}