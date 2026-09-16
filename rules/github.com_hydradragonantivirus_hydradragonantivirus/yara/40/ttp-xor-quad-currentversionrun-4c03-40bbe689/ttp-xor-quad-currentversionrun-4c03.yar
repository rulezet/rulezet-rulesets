rule TTP_XOR_QUAD_CurrentVersionRun_4c03 {
  strings:
    $key_4c03 = { 1f 6c [2] 3b 62 [2] 10 4e [2] 3e 6c [2] 2a 77 [2] 25 6d [2] 3b 70 [2] 39 71 [2] 22 77 [2] 3e 70 [2] 22 5f }

  condition:
    any of them
}