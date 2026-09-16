rule TTP_XOR_QUAD_CurrentVersionRun_1916 {
  strings:
    $key_1916 = { 4a 79 [2] 6e 77 [2] 45 5b [2] 6b 79 [2] 7f 62 [2] 70 78 [2] 6e 65 [2] 6c 64 [2] 77 62 [2] 6b 65 [2] 77 4a }

  condition:
    any of them
}