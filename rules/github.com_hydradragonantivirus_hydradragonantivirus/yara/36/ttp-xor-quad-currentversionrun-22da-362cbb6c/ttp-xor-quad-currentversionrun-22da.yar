rule TTP_XOR_QUAD_CurrentVersionRun_22da {
  strings:
    $key_22da = { 71 b5 [2] 55 bb [2] 7e 97 [2] 50 b5 [2] 44 ae [2] 4b b4 [2] 55 a9 [2] 57 a8 [2] 4c ae [2] 50 a9 [2] 4c 86 }

  condition:
    any of them
}