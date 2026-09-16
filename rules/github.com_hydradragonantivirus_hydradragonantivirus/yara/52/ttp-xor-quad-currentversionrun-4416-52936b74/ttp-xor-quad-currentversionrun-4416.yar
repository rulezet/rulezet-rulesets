rule TTP_XOR_QUAD_CurrentVersionRun_4416 {
  strings:
    $key_4416 = { 17 79 [2] 33 77 [2] 18 5b [2] 36 79 [2] 22 62 [2] 2d 78 [2] 33 65 [2] 31 64 [2] 2a 62 [2] 36 65 [2] 2a 4a }

  condition:
    any of them
}