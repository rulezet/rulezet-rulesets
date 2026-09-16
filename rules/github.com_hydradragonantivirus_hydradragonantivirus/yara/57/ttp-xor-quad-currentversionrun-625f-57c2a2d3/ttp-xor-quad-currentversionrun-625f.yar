rule TTP_XOR_QUAD_CurrentVersionRun_625f {
  strings:
    $key_625f = { 31 30 [2] 15 3e [2] 3e 12 [2] 10 30 [2] 04 2b [2] 0b 31 [2] 15 2c [2] 17 2d [2] 0c 2b [2] 10 2c [2] 0c 03 }

  condition:
    any of them
}