rule TTP_XOR_QUAD_CurrentVersionRun_5bef {
  strings:
    $key_5bef = { 08 80 [2] 2c 8e [2] 07 a2 [2] 29 80 [2] 3d 9b [2] 32 81 [2] 2c 9c [2] 2e 9d [2] 35 9b [2] 29 9c [2] 35 b3 }

  condition:
    any of them
}