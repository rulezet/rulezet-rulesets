rule TTP_XOR_QUAD_CurrentVersionRun_e5da {
  strings:
    $key_e5da = { b6 b5 [2] 92 bb [2] b9 97 [2] 97 b5 [2] 83 ae [2] 8c b4 [2] 92 a9 [2] 90 a8 [2] 8b ae [2] 97 a9 [2] 8b 86 }

  condition:
    any of them
}