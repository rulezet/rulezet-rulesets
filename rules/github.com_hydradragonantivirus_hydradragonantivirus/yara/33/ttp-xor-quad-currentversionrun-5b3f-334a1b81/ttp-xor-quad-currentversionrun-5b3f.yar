rule TTP_XOR_QUAD_CurrentVersionRun_5b3f {
  strings:
    $key_5b3f = { 08 50 [2] 2c 5e [2] 07 72 [2] 29 50 [2] 3d 4b [2] 32 51 [2] 2c 4c [2] 2e 4d [2] 35 4b [2] 29 4c [2] 35 63 }

  condition:
    any of them
}