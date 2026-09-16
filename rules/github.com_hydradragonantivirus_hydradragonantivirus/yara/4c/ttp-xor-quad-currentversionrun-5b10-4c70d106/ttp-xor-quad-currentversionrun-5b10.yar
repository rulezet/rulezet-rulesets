rule TTP_XOR_QUAD_CurrentVersionRun_5b10 {
  strings:
    $key_5b10 = { 08 7f [2] 2c 71 [2] 07 5d [2] 29 7f [2] 3d 64 [2] 32 7e [2] 2c 63 [2] 2e 62 [2] 35 64 [2] 29 63 [2] 35 4c }

  condition:
    any of them
}