rule TTP_XOR_QUAD_CurrentVersionRun_2a4b {
  strings:
    $key_2a4b = { 79 24 [2] 5d 2a [2] 76 06 [2] 58 24 [2] 4c 3f [2] 43 25 [2] 5d 38 [2] 5f 39 [2] 44 3f [2] 58 38 [2] 44 17 }

  condition:
    any of them
}