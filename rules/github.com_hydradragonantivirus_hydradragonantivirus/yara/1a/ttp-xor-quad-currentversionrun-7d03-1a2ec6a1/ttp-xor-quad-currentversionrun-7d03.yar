rule TTP_XOR_QUAD_CurrentVersionRun_7d03 {
  strings:
    $key_7d03 = { 2e 6c [2] 0a 62 [2] 21 4e [2] 0f 6c [2] 1b 77 [2] 14 6d [2] 0a 70 [2] 08 71 [2] 13 77 [2] 0f 70 [2] 13 5f }

  condition:
    any of them
}