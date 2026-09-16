rule TTP_XOR_QUAD_CurrentVersionRun_47da {
  strings:
    $key_47da = { 14 b5 [2] 30 bb [2] 1b 97 [2] 35 b5 [2] 21 ae [2] 2e b4 [2] 30 a9 [2] 32 a8 [2] 29 ae [2] 35 a9 [2] 29 86 }

  condition:
    any of them
}