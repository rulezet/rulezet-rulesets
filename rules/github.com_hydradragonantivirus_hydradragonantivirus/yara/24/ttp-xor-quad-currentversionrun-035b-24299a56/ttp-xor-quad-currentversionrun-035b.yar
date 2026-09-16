rule TTP_XOR_QUAD_CurrentVersionRun_035b {
  strings:
    $key_035b = { 50 34 [2] 74 3a [2] 5f 16 [2] 71 34 [2] 65 2f [2] 6a 35 [2] 74 28 [2] 76 29 [2] 6d 2f [2] 71 28 [2] 6d 07 }

  condition:
    any of them
}