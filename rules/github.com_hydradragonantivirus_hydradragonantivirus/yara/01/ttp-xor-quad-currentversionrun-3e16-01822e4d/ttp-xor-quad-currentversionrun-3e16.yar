rule TTP_XOR_QUAD_CurrentVersionRun_3e16 {
  strings:
    $key_3e16 = { 6d 79 [2] 49 77 [2] 62 5b [2] 4c 79 [2] 58 62 [2] 57 78 [2] 49 65 [2] 4b 64 [2] 50 62 [2] 4c 65 [2] 50 4a }

  condition:
    any of them
}