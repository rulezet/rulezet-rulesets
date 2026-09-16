rule TTP_XOR_QUAD_CurrentVersionRun_6d16 {
  strings:
    $key_6d16 = { 3e 79 [2] 1a 77 [2] 31 5b [2] 1f 79 [2] 0b 62 [2] 04 78 [2] 1a 65 [2] 18 64 [2] 03 62 [2] 1f 65 [2] 03 4a }

  condition:
    any of them
}