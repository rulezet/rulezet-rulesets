rule TTP_XOR_QUAD_CurrentVersionRun_26da {
  strings:
    $key_26da = { 75 b5 [2] 51 bb [2] 7a 97 [2] 54 b5 [2] 40 ae [2] 4f b4 [2] 51 a9 [2] 53 a8 [2] 48 ae [2] 54 a9 [2] 48 86 }

  condition:
    any of them
}