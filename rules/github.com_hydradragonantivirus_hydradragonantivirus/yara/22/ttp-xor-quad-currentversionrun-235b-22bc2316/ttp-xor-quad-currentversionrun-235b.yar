rule TTP_XOR_QUAD_CurrentVersionRun_235b {
  strings:
    $key_235b = { 70 34 [2] 54 3a [2] 7f 16 [2] 51 34 [2] 45 2f [2] 4a 35 [2] 54 28 [2] 56 29 [2] 4d 2f [2] 51 28 [2] 4d 07 }

  condition:
    any of them
}