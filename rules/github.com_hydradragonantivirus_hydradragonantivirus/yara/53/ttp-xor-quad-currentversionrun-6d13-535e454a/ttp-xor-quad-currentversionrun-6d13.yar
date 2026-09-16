rule TTP_XOR_QUAD_CurrentVersionRun_6d13 {
  strings:
    $key_6d13 = { 3e 7c [2] 1a 72 [2] 31 5e [2] 1f 7c [2] 0b 67 [2] 04 7d [2] 1a 60 [2] 18 61 [2] 03 67 [2] 1f 60 [2] 03 4f }

  condition:
    any of them
}