rule TTP_XOR_QUAD_CurrentVersionRun_f137 {
  strings:
    $key_f137 = { a2 58 [2] 86 56 [2] ad 7a [2] 83 58 [2] 97 43 [2] 98 59 [2] 86 44 [2] 84 45 [2] 9f 43 [2] 83 44 [2] 9f 6b }

  condition:
    any of them
}