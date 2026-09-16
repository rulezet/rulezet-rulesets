rule TTP_XOR_QUAD_CurrentVersionRun_67d5 {
  strings:
    $key_67d5 = { 34 ba [2] 10 b4 [2] 3b 98 [2] 15 ba [2] 01 a1 [2] 0e bb [2] 10 a6 [2] 12 a7 [2] 09 a1 [2] 15 a6 [2] 09 89 }

  condition:
    any of them
}