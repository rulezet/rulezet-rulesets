rule TTP_XOR_QUAD_CurrentVersionRun_07d5 {
  strings:
    $key_07d5 = { 54 ba [2] 70 b4 [2] 5b 98 [2] 75 ba [2] 61 a1 [2] 6e bb [2] 70 a6 [2] 72 a7 [2] 69 a1 [2] 75 a6 [2] 69 89 }

  condition:
    any of them
}