rule TTP_XOR_QUAD_CurrentVersionRun_72da {
  strings:
    $key_72da = { 21 b5 [2] 05 bb [2] 2e 97 [2] 00 b5 [2] 14 ae [2] 1b b4 [2] 05 a9 [2] 07 a8 [2] 1c ae [2] 00 a9 [2] 1c 86 }

  condition:
    any of them
}