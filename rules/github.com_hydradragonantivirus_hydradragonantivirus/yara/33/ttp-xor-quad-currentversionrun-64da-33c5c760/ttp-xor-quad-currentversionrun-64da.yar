rule TTP_XOR_QUAD_CurrentVersionRun_64da {
  strings:
    $key_64da = { 37 b5 [2] 13 bb [2] 38 97 [2] 16 b5 [2] 02 ae [2] 0d b4 [2] 13 a9 [2] 11 a8 [2] 0a ae [2] 16 a9 [2] 0a 86 }

  condition:
    any of them
}