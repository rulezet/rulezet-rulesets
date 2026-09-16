rule TTP_XOR_QUAD_CurrentVersionRun_44da {
  strings:
    $key_44da = { 17 b5 [2] 33 bb [2] 18 97 [2] 36 b5 [2] 22 ae [2] 2d b4 [2] 33 a9 [2] 31 a8 [2] 2a ae [2] 36 a9 [2] 2a 86 }

  condition:
    any of them
}