rule TTP_XOR_QUAD_CurrentVersionRun_595e {
  strings:
    $key_595e = { 0a 31 [2] 2e 3f [2] 05 13 [2] 2b 31 [2] 3f 2a [2] 30 30 [2] 2e 2d [2] 2c 2c [2] 37 2a [2] 2b 2d [2] 37 02 }

  condition:
    any of them
}