rule TTP_XOR_QUAD_CurrentVersionRun_3916 {
  strings:
    $key_3916 = { 6a 79 [2] 4e 77 [2] 65 5b [2] 4b 79 [2] 5f 62 [2] 50 78 [2] 4e 65 [2] 4c 64 [2] 57 62 [2] 4b 65 [2] 57 4a }

  condition:
    any of them
}