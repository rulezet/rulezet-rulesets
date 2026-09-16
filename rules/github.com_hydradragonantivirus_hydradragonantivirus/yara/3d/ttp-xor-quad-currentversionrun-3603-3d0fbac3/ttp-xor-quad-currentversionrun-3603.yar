rule TTP_XOR_QUAD_CurrentVersionRun_3603 {
  strings:
    $key_3603 = { 65 6c [2] 41 62 [2] 6a 4e [2] 44 6c [2] 50 77 [2] 5f 6d [2] 41 70 [2] 43 71 [2] 58 77 [2] 44 70 [2] 58 5f }

  condition:
    any of them
}