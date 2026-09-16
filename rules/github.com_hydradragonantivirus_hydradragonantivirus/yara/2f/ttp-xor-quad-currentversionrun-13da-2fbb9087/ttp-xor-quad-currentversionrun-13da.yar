rule TTP_XOR_QUAD_CurrentVersionRun_13da {
  strings:
    $key_13da = { 40 b5 [2] 64 bb [2] 4f 97 [2] 61 b5 [2] 75 ae [2] 7a b4 [2] 64 a9 [2] 66 a8 [2] 7d ae [2] 61 a9 [2] 7d 86 }

  condition:
    any of them
}