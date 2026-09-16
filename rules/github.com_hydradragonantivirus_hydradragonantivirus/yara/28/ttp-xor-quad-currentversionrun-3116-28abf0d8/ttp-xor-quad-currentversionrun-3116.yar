rule TTP_XOR_QUAD_CurrentVersionRun_3116 {
  strings:
    $key_3116 = { 62 79 [2] 46 77 [2] 6d 5b [2] 43 79 [2] 57 62 [2] 58 78 [2] 46 65 [2] 44 64 [2] 5f 62 [2] 43 65 [2] 5f 4a }

  condition:
    any of them
}