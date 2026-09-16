rule TTP_XOR_QUAD_CurrentVersionRun_3c16 {
  strings:
    $key_3c16 = { 6f 79 [2] 4b 77 [2] 60 5b [2] 4e 79 [2] 5a 62 [2] 55 78 [2] 4b 65 [2] 49 64 [2] 52 62 [2] 4e 65 [2] 52 4a }

  condition:
    any of them
}