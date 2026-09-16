rule TTP_XOR_QUAD_CurrentVersionRun_45da {
  strings:
    $key_45da = { 16 b5 [2] 32 bb [2] 19 97 [2] 37 b5 [2] 23 ae [2] 2c b4 [2] 32 a9 [2] 30 a8 [2] 2b ae [2] 37 a9 [2] 2b 86 }

  condition:
    any of them
}