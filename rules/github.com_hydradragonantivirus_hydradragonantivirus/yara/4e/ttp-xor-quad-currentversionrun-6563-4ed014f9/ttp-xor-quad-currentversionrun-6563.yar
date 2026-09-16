rule TTP_XOR_QUAD_CurrentVersionRun_6563 {
  strings:
    $key_6563 = { 36 0c [2] 12 02 [2] 39 2e [2] 17 0c [2] 03 17 [2] 0c 0d [2] 12 10 [2] 10 11 [2] 0b 17 [2] 17 10 [2] 0b 3f }

  condition:
    any of them
}