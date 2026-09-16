rule TTP_XOR_QUAD_CurrentVersionRun_1003 {
  strings:
    $key_1003 = { 43 6c [2] 67 62 [2] 4c 4e [2] 62 6c [2] 76 77 [2] 79 6d [2] 67 70 [2] 65 71 [2] 7e 77 [2] 62 70 [2] 7e 5f }

  condition:
    any of them
}