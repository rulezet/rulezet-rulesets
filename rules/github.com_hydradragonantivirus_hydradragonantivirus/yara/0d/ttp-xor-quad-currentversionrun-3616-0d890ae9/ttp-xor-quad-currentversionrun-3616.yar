rule TTP_XOR_QUAD_CurrentVersionRun_3616 {
  strings:
    $key_3616 = { 65 79 [2] 41 77 [2] 6a 5b [2] 44 79 [2] 50 62 [2] 5f 78 [2] 41 65 [2] 43 64 [2] 58 62 [2] 44 65 [2] 58 4a }

  condition:
    any of them
}