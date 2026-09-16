rule TTP_XOR_QUAD_CurrentVersionRun_5b7f {
  strings:
    $key_5b7f = { 08 10 [2] 2c 1e [2] 07 32 [2] 29 10 [2] 3d 0b [2] 32 11 [2] 2c 0c [2] 2e 0d [2] 35 0b [2] 29 0c [2] 35 23 }

  condition:
    any of them
}