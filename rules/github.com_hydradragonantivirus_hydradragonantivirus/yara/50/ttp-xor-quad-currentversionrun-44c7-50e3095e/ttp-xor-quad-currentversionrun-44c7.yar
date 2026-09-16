rule TTP_XOR_QUAD_CurrentVersionRun_44c7 {
  strings:
    $key_44c7 = { 17 a8 [2] 33 a6 [2] 18 8a [2] 36 a8 [2] 22 b3 [2] 2d a9 [2] 33 b4 [2] 31 b5 [2] 2a b3 [2] 36 b4 [2] 2a 9b }

  condition:
    any of them
}