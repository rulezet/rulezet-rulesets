rule TTP_XOR_QUAD_CurrentVersionRun_4f2b {
  strings:
    $key_4f2b = { 1c 44 [2] 38 4a [2] 13 66 [2] 3d 44 [2] 29 5f [2] 26 45 [2] 38 58 [2] 3a 59 [2] 21 5f [2] 3d 58 [2] 21 77 }

  condition:
    any of them
}