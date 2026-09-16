rule TTP_XOR_QUAD_CurrentVersionRun_244b {
  strings:
    $key_244b = { 77 24 [2] 53 2a [2] 78 06 [2] 56 24 [2] 42 3f [2] 4d 25 [2] 53 38 [2] 51 39 [2] 4a 3f [2] 56 38 [2] 4a 17 }

  condition:
    any of them
}