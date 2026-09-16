rule TTP_XOR_QUAD_CurrentVersionRun_5b30 {
  strings:
    $key_5b30 = { 08 5f [2] 2c 51 [2] 07 7d [2] 29 5f [2] 3d 44 [2] 32 5e [2] 2c 43 [2] 2e 42 [2] 35 44 [2] 29 43 [2] 35 6c }

  condition:
    any of them
}