rule TTP_XOR_QUAD_CurrentVersionRun_4550 {
  strings:
    $key_4550 = { 16 3f [2] 32 31 [2] 19 1d [2] 37 3f [2] 23 24 [2] 2c 3e [2] 32 23 [2] 30 22 [2] 2b 24 [2] 37 23 [2] 2b 0c }

  condition:
    any of them
}