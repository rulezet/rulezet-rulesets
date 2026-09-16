rule TTP_XOR_QUAD_CurrentVersionRun_5be1 {
  strings:
    $key_5be1 = { 08 8e [2] 2c 80 [2] 07 ac [2] 29 8e [2] 3d 95 [2] 32 8f [2] 2c 92 [2] 2e 93 [2] 35 95 [2] 29 92 [2] 35 bd }

  condition:
    any of them
}