rule TTP_XOR_QUAD_CurrentVersionRun_6816 {
  strings:
    $key_6816 = { 3b 79 [2] 1f 77 [2] 34 5b [2] 1a 79 [2] 0e 62 [2] 01 78 [2] 1f 65 [2] 1d 64 [2] 06 62 [2] 1a 65 [2] 06 4a }

  condition:
    any of them
}