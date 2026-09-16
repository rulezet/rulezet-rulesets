rule TTP_XOR_QUAD_CurrentVersionRun_5bff {
  strings:
    $key_5bff = { 08 90 [2] 2c 9e [2] 07 b2 [2] 29 90 [2] 3d 8b [2] 32 91 [2] 2c 8c [2] 2e 8d [2] 35 8b [2] 29 8c [2] 35 a3 }

  condition:
    any of them
}