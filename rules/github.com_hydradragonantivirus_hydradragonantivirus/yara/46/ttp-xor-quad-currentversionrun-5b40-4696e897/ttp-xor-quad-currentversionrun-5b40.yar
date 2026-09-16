rule TTP_XOR_QUAD_CurrentVersionRun_5b40 {
  strings:
    $key_5b40 = { 08 2f [2] 2c 21 [2] 07 0d [2] 29 2f [2] 3d 34 [2] 32 2e [2] 2c 33 [2] 2e 32 [2] 35 34 [2] 29 33 [2] 35 1c }

  condition:
    any of them
}