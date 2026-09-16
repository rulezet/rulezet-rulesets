rule TTP_XOR_QUAD_CurrentVersionRun_23d7 {
  strings:
    $key_23d7 = { 70 b8 [2] 54 b6 [2] 7f 9a [2] 51 b8 [2] 45 a3 [2] 4a b9 [2] 54 a4 [2] 56 a5 [2] 4d a3 [2] 51 a4 [2] 4d 8b }

  condition:
    any of them
}