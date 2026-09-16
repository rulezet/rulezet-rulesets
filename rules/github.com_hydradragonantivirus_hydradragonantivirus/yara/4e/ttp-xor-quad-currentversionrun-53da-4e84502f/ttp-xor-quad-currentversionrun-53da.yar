rule TTP_XOR_QUAD_CurrentVersionRun_53da {
  strings:
    $key_53da = { 00 b5 [2] 24 bb [2] 0f 97 [2] 21 b5 [2] 35 ae [2] 3a b4 [2] 24 a9 [2] 26 a8 [2] 3d ae [2] 21 a9 [2] 3d 86 }

  condition:
    any of them
}