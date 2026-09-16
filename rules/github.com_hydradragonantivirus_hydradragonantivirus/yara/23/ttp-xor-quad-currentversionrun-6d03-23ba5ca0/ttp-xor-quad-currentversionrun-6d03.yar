rule TTP_XOR_QUAD_CurrentVersionRun_6d03 {
  strings:
    $key_6d03 = { 3e 6c [2] 1a 62 [2] 31 4e [2] 1f 6c [2] 0b 77 [2] 04 6d [2] 1a 70 [2] 18 71 [2] 03 77 [2] 1f 70 [2] 03 5f }

  condition:
    any of them
}