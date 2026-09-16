rule TTP_XOR_QUAD_CurrentVersionRun_7f63 {
  strings:
    $key_7f63 = { 2c 0c [2] 08 02 [2] 23 2e [2] 0d 0c [2] 19 17 [2] 16 0d [2] 08 10 [2] 0a 11 [2] 11 17 [2] 0d 10 [2] 11 3f }

  condition:
    any of them
}