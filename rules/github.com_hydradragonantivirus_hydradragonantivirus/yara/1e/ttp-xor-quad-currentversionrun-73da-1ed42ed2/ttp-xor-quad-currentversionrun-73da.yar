rule TTP_XOR_QUAD_CurrentVersionRun_73da {
  strings:
    $key_73da = { 20 b5 [2] 04 bb [2] 2f 97 [2] 01 b5 [2] 15 ae [2] 1a b4 [2] 04 a9 [2] 06 a8 [2] 1d ae [2] 01 a9 [2] 1d 86 }

  condition:
    any of them
}