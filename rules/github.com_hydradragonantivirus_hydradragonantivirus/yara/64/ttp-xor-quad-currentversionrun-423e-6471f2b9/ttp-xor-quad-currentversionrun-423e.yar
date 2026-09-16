rule TTP_XOR_QUAD_CurrentVersionRun_423e {
  strings:
    $key_423e = { 11 51 [2] 35 5f [2] 1e 73 [2] 30 51 [2] 24 4a [2] 2b 50 [2] 35 4d [2] 37 4c [2] 2c 4a [2] 30 4d [2] 2c 62 }

  condition:
    any of them
}