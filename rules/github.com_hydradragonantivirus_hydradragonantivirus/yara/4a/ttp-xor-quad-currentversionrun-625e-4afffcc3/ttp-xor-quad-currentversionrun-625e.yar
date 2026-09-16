rule TTP_XOR_QUAD_CurrentVersionRun_625e {
  strings:
    $key_625e = { 31 31 [2] 15 3f [2] 3e 13 [2] 10 31 [2] 04 2a [2] 0b 30 [2] 15 2d [2] 17 2c [2] 0c 2a [2] 10 2d [2] 0c 02 }

  condition:
    any of them
}