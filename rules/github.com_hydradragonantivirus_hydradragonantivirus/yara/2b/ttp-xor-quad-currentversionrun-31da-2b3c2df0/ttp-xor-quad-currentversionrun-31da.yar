rule TTP_XOR_QUAD_CurrentVersionRun_31da {
  strings:
    $key_31da = { 62 b5 [2] 46 bb [2] 6d 97 [2] 43 b5 [2] 57 ae [2] 58 b4 [2] 46 a9 [2] 44 a8 [2] 5f ae [2] 43 a9 [2] 5f 86 }

  condition:
    any of them
}