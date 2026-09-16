rule TTP_XOR_QUAD_CurrentVersionRun_1c03 {
  strings:
    $key_1c03 = { 4f 6c [2] 6b 62 [2] 40 4e [2] 6e 6c [2] 7a 77 [2] 75 6d [2] 6b 70 [2] 69 71 [2] 72 77 [2] 6e 70 [2] 72 5f }

  condition:
    any of them
}