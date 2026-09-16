rule TTP_XOR_QUAD_CurrentVersionRun_5916 {
  strings:
    $key_5916 = { 0a 79 [2] 2e 77 [2] 05 5b [2] 2b 79 [2] 3f 62 [2] 30 78 [2] 2e 65 [2] 2c 64 [2] 37 62 [2] 2b 65 [2] 37 4a }

  condition:
    any of them
}