rule TTP_XOR_QUAD_CurrentVersionRun_2a27 {
  strings:
    $key_2a27 = { 79 48 [2] 5d 46 [2] 76 6a [2] 58 48 [2] 4c 53 [2] 43 49 [2] 5d 54 [2] 5f 55 [2] 44 53 [2] 58 54 [2] 44 7b }

  condition:
    any of them
}