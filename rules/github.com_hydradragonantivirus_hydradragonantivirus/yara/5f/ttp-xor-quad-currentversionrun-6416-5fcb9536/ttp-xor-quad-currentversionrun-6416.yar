rule TTP_XOR_QUAD_CurrentVersionRun_6416 {
  strings:
    $key_6416 = { 37 79 [2] 13 77 [2] 38 5b [2] 16 79 [2] 02 62 [2] 0d 78 [2] 13 65 [2] 11 64 [2] 0a 62 [2] 16 65 [2] 0a 4a }

  condition:
    any of them
}