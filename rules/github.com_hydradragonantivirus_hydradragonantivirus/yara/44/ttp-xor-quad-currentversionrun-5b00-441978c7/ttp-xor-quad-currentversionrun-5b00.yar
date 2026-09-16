rule TTP_XOR_QUAD_CurrentVersionRun_5b00 {
  strings:
    $key_5b00 = { 08 6f [2] 2c 61 [2] 07 4d [2] 29 6f [2] 3d 74 [2] 32 6e [2] 2c 73 [2] 2e 72 [2] 35 74 [2] 29 73 [2] 35 5c }

  condition:
    any of them
}