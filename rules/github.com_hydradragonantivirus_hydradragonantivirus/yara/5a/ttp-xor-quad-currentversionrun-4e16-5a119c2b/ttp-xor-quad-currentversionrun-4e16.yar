rule TTP_XOR_QUAD_CurrentVersionRun_4e16 {
  strings:
    $key_4e16 = { 1d 79 [2] 39 77 [2] 12 5b [2] 3c 79 [2] 28 62 [2] 27 78 [2] 39 65 [2] 3b 64 [2] 20 62 [2] 3c 65 [2] 20 4a }

  condition:
    any of them
}