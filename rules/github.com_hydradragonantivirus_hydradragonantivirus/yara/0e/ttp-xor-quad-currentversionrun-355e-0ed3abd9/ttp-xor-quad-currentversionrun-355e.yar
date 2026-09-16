rule TTP_XOR_QUAD_CurrentVersionRun_355e {
  strings:
    $key_355e = { 66 31 [2] 42 3f [2] 69 13 [2] 47 31 [2] 53 2a [2] 5c 30 [2] 42 2d [2] 40 2c [2] 5b 2a [2] 47 2d [2] 5b 02 }

  condition:
    any of them
}