rule TTP_XOR_QUAD_CurrentVersionRun_2f17 {
  strings:
    $key_2f17 = { 7c 78 [2] 58 76 [2] 73 5a [2] 5d 78 [2] 49 63 [2] 46 79 [2] 58 64 [2] 5a 65 [2] 41 63 [2] 5d 64 [2] 41 4b }

  condition:
    any of them
}