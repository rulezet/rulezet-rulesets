rule TTP_XOR_QUAD_CurrentVersionRun_7e63 {
  strings:
    $key_7e63 = { 2d 0c [2] 09 02 [2] 22 2e [2] 0c 0c [2] 18 17 [2] 17 0d [2] 09 10 [2] 0b 11 [2] 10 17 [2] 0c 10 [2] 10 3f }

  condition:
    any of them
}