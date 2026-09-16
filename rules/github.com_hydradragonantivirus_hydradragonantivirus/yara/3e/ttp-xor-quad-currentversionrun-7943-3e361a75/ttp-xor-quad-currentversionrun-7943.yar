rule TTP_XOR_QUAD_CurrentVersionRun_7943 {
  strings:
    $key_7943 = { 2a 2c [2] 0e 22 [2] 25 0e [2] 0b 2c [2] 1f 37 [2] 10 2d [2] 0e 30 [2] 0c 31 [2] 17 37 [2] 0b 30 [2] 17 1f }

  condition:
    any of them
}