rule TTP_XOR_QUAD_CurrentVersionRun_25da {
  strings:
    $key_25da = { 76 b5 [2] 52 bb [2] 79 97 [2] 57 b5 [2] 43 ae [2] 4c b4 [2] 52 a9 [2] 50 a8 [2] 4b ae [2] 57 a9 [2] 4b 86 }

  condition:
    any of them
}