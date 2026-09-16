rule TTP_XOR_QUAD_CurrentVersionRun_17da {
  strings:
    $key_17da = { 44 b5 [2] 60 bb [2] 4b 97 [2] 65 b5 [2] 71 ae [2] 7e b4 [2] 60 a9 [2] 62 a8 [2] 79 ae [2] 65 a9 [2] 79 86 }

  condition:
    any of them
}