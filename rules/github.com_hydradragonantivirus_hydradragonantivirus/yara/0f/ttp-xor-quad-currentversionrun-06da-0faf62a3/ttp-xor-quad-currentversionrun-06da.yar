rule TTP_XOR_QUAD_CurrentVersionRun_06da {
  strings:
    $key_06da = { 55 b5 [2] 71 bb [2] 5a 97 [2] 74 b5 [2] 60 ae [2] 6f b4 [2] 71 a9 [2] 73 a8 [2] 68 ae [2] 74 a9 [2] 68 86 }

  condition:
    any of them
}