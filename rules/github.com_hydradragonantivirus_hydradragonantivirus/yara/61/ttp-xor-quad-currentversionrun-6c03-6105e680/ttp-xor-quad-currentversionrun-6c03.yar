rule TTP_XOR_QUAD_CurrentVersionRun_6c03 {
  strings:
    $key_6c03 = { 3f 6c [2] 1b 62 [2] 30 4e [2] 1e 6c [2] 0a 77 [2] 05 6d [2] 1b 70 [2] 19 71 [2] 02 77 [2] 1e 70 [2] 02 5f }

  condition:
    any of them
}