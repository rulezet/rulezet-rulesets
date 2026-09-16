rule TTP_XOR_QUAD_CurrentVersionRun_455e {
  strings:
    $key_455e = { 16 31 [2] 32 3f [2] 19 13 [2] 37 31 [2] 23 2a [2] 2c 30 [2] 32 2d [2] 30 2c [2] 2b 2a [2] 37 2d [2] 2b 02 }

  condition:
    any of them
}