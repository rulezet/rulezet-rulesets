rule TTP_XOR_QUAD_CurrentVersionRun_70f2 {
  strings:
    $key_70f2 = { 23 9d [2] 07 93 [2] 2c bf [2] 02 9d [2] 16 86 [2] 19 9c [2] 07 81 [2] 05 80 [2] 1e 86 [2] 02 81 [2] 1e ae }

  condition:
    any of them
}