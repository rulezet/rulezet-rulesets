rule TTP_XOR_QUAD_CurrentVersionRun_1c16 {
  strings:
    $key_1c16 = { 4f 79 [2] 6b 77 [2] 40 5b [2] 6e 79 [2] 7a 62 [2] 75 78 [2] 6b 65 [2] 69 64 [2] 72 62 [2] 6e 65 [2] 72 4a }

  condition:
    any of them
}