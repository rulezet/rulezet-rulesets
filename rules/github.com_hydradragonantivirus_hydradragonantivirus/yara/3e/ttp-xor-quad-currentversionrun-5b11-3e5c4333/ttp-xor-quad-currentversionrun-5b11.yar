rule TTP_XOR_QUAD_CurrentVersionRun_5b11 {
  strings:
    $key_5b11 = { 08 7e [2] 2c 70 [2] 07 5c [2] 29 7e [2] 3d 65 [2] 32 7f [2] 2c 62 [2] 2e 63 [2] 35 65 [2] 29 62 [2] 35 4d }

  condition:
    any of them
}