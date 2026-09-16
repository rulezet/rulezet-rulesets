rule TTP_XOR_QUAD_CurrentVersionRun_4f37 {
  strings:
    $key_4f37 = { 1c 58 [2] 38 56 [2] 13 7a [2] 3d 58 [2] 29 43 [2] 26 59 [2] 38 44 [2] 3a 45 [2] 21 43 [2] 3d 44 [2] 21 6b }

  condition:
    any of them
}