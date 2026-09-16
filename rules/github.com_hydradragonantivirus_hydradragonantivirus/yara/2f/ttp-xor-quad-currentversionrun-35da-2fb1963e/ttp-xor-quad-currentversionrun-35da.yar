rule TTP_XOR_QUAD_CurrentVersionRun_35da {
  strings:
    $key_35da = { 66 b5 [2] 42 bb [2] 69 97 [2] 47 b5 [2] 53 ae [2] 5c b4 [2] 42 a9 [2] 40 a8 [2] 5b ae [2] 47 a9 [2] 5b 86 }

  condition:
    any of them
}