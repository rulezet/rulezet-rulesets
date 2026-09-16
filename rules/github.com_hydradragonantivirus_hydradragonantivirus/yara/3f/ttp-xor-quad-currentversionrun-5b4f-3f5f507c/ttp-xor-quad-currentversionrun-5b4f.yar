rule TTP_XOR_QUAD_CurrentVersionRun_5b4f {
  strings:
    $key_5b4f = { 08 20 [2] 2c 2e [2] 07 02 [2] 29 20 [2] 3d 3b [2] 32 21 [2] 2c 3c [2] 2e 3d [2] 35 3b [2] 29 3c [2] 35 13 }

  condition:
    any of them
}