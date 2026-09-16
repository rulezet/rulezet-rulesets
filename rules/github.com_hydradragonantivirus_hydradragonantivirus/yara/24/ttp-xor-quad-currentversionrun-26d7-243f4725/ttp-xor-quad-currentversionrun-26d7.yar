rule TTP_XOR_QUAD_CurrentVersionRun_26d7 {
  strings:
    $key_26d7 = { 75 b8 [2] 51 b6 [2] 7a 9a [2] 54 b8 [2] 40 a3 [2] 4f b9 [2] 51 a4 [2] 53 a5 [2] 48 a3 [2] 54 a4 [2] 48 8b }

  condition:
    any of them
}