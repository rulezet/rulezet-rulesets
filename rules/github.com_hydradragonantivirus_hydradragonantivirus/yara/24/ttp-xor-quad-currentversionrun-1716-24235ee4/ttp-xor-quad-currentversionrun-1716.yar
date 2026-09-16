rule TTP_XOR_QUAD_CurrentVersionRun_1716 {
  strings:
    $key_1716 = { 44 79 [2] 60 77 [2] 4b 5b [2] 65 79 [2] 71 62 [2] 7e 78 [2] 60 65 [2] 62 64 [2] 79 62 [2] 65 65 [2] 79 4a }

  condition:
    any of them
}