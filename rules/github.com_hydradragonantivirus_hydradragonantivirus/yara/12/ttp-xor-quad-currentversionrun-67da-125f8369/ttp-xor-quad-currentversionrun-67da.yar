rule TTP_XOR_QUAD_CurrentVersionRun_67da {
  strings:
    $key_67da = { 34 b5 [2] 10 bb [2] 3b 97 [2] 15 b5 [2] 01 ae [2] 0e b4 [2] 10 a9 [2] 12 a8 [2] 09 ae [2] 15 a9 [2] 09 86 }

  condition:
    any of them
}