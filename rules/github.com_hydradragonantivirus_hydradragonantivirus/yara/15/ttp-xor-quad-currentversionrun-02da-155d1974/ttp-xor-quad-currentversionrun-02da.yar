rule TTP_XOR_QUAD_CurrentVersionRun_02da {
  strings:
    $key_02da = { 51 b5 [2] 75 bb [2] 5e 97 [2] 70 b5 [2] 64 ae [2] 6b b4 [2] 75 a9 [2] 77 a8 [2] 6c ae [2] 70 a9 [2] 6c 86 }

  condition:
    any of them
}