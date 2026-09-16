rule TTP_XOR_QUAD_CurrentVersionRun_76da {
  strings:
    $key_76da = { 25 b5 [2] 01 bb [2] 2a 97 [2] 04 b5 [2] 10 ae [2] 1f b4 [2] 01 a9 [2] 03 a8 [2] 18 ae [2] 04 a9 [2] 18 86 }

  condition:
    any of them
}