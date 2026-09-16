rule TTP_XOR_QUAD_CurrentVersionRun_5b31 {
  strings:
    $key_5b31 = { 08 5e [2] 2c 50 [2] 07 7c [2] 29 5e [2] 3d 45 [2] 32 5f [2] 2c 42 [2] 2e 43 [2] 35 45 [2] 29 42 [2] 35 6d }

  condition:
    any of them
}