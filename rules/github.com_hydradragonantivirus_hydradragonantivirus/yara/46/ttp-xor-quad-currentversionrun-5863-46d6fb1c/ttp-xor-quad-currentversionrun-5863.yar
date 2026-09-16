rule TTP_XOR_QUAD_CurrentVersionRun_5863 {
  strings:
    $key_5863 = { 0b 0c [2] 2f 02 [2] 04 2e [2] 2a 0c [2] 3e 17 [2] 31 0d [2] 2f 10 [2] 2d 11 [2] 36 17 [2] 2a 10 [2] 36 3f }

  condition:
    any of them
}