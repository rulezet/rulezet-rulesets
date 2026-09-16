rule TTP_XOR_QUAD_CurrentVersionRun_7f13 {
  strings:
    $key_7f13 = { 2c 7c [2] 08 72 [2] 23 5e [2] 0d 7c [2] 19 67 [2] 16 7d [2] 08 60 [2] 0a 61 [2] 11 67 [2] 0d 60 [2] 11 4f }

  condition:
    any of them
}