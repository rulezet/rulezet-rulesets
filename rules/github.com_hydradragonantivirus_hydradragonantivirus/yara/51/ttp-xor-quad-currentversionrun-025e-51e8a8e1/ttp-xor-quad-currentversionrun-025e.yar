rule TTP_XOR_QUAD_CurrentVersionRun_025e {
  strings:
    $key_025e = { 51 31 [2] 75 3f [2] 5e 13 [2] 70 31 [2] 64 2a [2] 6b 30 [2] 75 2d [2] 77 2c [2] 6c 2a [2] 70 2d [2] 6c 02 }

  condition:
    any of them
}