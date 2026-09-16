rule TTP_XOR_QUAD_CurrentVersionRun_7f03 {
  strings:
    $key_7f03 = { 2c 6c [2] 08 62 [2] 23 4e [2] 0d 6c [2] 19 77 [2] 16 6d [2] 08 70 [2] 0a 71 [2] 11 77 [2] 0d 70 [2] 11 5f }

  condition:
    any of them
}