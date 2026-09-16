rule TTP_XOR_QUAD_CurrentVersionRun_1703 {
  strings:
    $key_1703 = { 44 6c [2] 60 62 [2] 4b 4e [2] 65 6c [2] 71 77 [2] 7e 6d [2] 60 70 [2] 62 71 [2] 79 77 [2] 65 70 [2] 79 5f }

  condition:
    any of them
}