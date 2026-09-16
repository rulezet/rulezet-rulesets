rule TTP_XOR_QUAD_CurrentVersionRun_36da {
  strings:
    $key_36da = { 65 b5 [2] 41 bb [2] 6a 97 [2] 44 b5 [2] 50 ae [2] 5f b4 [2] 41 a9 [2] 43 a8 [2] 58 ae [2] 44 a9 [2] 58 86 }

  condition:
    any of them
}