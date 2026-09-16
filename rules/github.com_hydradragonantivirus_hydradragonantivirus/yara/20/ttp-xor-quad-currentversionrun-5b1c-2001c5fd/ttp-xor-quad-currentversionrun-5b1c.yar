rule TTP_XOR_QUAD_CurrentVersionRun_5b1c {
  strings:
    $key_5b1c = { 08 73 [2] 2c 7d [2] 07 51 [2] 29 73 [2] 3d 68 [2] 32 72 [2] 2c 6f [2] 2e 6e [2] 35 68 [2] 29 6f [2] 35 40 }

  condition:
    any of them
}