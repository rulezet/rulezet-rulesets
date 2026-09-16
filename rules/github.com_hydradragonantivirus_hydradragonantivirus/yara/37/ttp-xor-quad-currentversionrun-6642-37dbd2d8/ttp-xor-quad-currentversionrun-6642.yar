rule TTP_XOR_QUAD_CurrentVersionRun_6642 {
  strings:
    $key_6642 = { 35 2d [2] 11 23 [2] 3a 0f [2] 14 2d [2] 00 36 [2] 0f 2c [2] 11 31 [2] 13 30 [2] 08 36 [2] 14 31 [2] 08 1e }

  condition:
    any of them
}