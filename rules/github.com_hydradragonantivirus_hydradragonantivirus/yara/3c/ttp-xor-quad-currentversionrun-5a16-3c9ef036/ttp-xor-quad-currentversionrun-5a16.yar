rule TTP_XOR_QUAD_CurrentVersionRun_5a16 {
  strings:
    $key_5a16 = { 09 79 [2] 2d 77 [2] 06 5b [2] 28 79 [2] 3c 62 [2] 33 78 [2] 2d 65 [2] 2f 64 [2] 34 62 [2] 28 65 [2] 34 4a }

  condition:
    any of them
}