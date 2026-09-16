rule TTP_XOR_QUAD_CurrentVersionRun_4424 {
  strings:
    $key_4424 = { 17 4b [2] 33 45 [2] 18 69 [2] 36 4b [2] 22 50 [2] 2d 4a [2] 33 57 [2] 31 56 [2] 2a 50 [2] 36 57 [2] 2a 78 }

  condition:
    any of them
}