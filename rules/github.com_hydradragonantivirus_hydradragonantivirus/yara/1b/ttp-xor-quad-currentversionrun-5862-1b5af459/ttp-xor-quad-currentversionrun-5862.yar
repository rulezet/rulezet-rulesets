rule TTP_XOR_QUAD_CurrentVersionRun_5862 {
  strings:
    $key_5862 = { 0b 0d [2] 2f 03 [2] 04 2f [2] 2a 0d [2] 3e 16 [2] 31 0c [2] 2f 11 [2] 2d 10 [2] 36 16 [2] 2a 11 [2] 36 3e }

  condition:
    any of them
}