rule TTP_XOR_QUAD_CurrentVersionRun_1016 {
  strings:
    $key_1016 = { 43 79 [2] 67 77 [2] 4c 5b [2] 62 79 [2] 76 62 [2] 79 78 [2] 67 65 [2] 65 64 [2] 7e 62 [2] 62 65 [2] 7e 4a }

  condition:
    any of them
}