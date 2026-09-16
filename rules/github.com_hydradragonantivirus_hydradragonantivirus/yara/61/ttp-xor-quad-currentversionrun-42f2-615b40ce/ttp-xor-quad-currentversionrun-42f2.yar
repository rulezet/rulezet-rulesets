rule TTP_XOR_QUAD_CurrentVersionRun_42f2 {
  strings:
    $key_42f2 = { 11 9d [2] 35 93 [2] 1e bf [2] 30 9d [2] 24 86 [2] 2b 9c [2] 35 81 [2] 37 80 [2] 2c 86 [2] 30 81 [2] 2c ae }

  condition:
    any of them
}