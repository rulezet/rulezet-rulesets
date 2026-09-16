rule TTP_XOR_QUAD_CurrentVersionRun_5bfd {
  strings:
    $key_5bfd = { 08 92 [2] 2c 9c [2] 07 b0 [2] 29 92 [2] 3d 89 [2] 32 93 [2] 2c 8e [2] 2e 8f [2] 35 89 [2] 29 8e [2] 35 a1 }

  condition:
    any of them
}