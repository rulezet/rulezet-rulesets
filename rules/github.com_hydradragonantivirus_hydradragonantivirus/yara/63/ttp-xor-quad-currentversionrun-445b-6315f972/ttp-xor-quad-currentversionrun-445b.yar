rule TTP_XOR_QUAD_CurrentVersionRun_445b {
  strings:
    $key_445b = { 17 34 [2] 33 3a [2] 18 16 [2] 36 34 [2] 22 2f [2] 2d 35 [2] 33 28 [2] 31 29 [2] 2a 2f [2] 36 28 [2] 2a 07 }

  condition:
    any of them
}