rule TTP_XOR_QUAD_CurrentVersionRun_21da {
  strings:
    $key_21da = { 72 b5 [2] 56 bb [2] 7d 97 [2] 53 b5 [2] 47 ae [2] 48 b4 [2] 56 a9 [2] 54 a8 [2] 4f ae [2] 53 a9 [2] 4f 86 }

  condition:
    any of them
}