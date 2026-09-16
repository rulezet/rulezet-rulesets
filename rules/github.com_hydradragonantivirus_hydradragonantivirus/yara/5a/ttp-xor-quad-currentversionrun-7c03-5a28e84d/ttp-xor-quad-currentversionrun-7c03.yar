rule TTP_XOR_QUAD_CurrentVersionRun_7c03 {
  strings:
    $key_7c03 = { 2f 6c [2] 0b 62 [2] 20 4e [2] 0e 6c [2] 1a 77 [2] 15 6d [2] 0b 70 [2] 09 71 [2] 12 77 [2] 0e 70 [2] 12 5f }

  condition:
    any of them
}