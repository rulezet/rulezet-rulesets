rule TTP_XOR_QUAD_CurrentVersionRun_5e31 {
  strings:
    $key_5e31 = { 0d 5e [2] 29 50 [2] 02 7c [2] 2c 5e [2] 38 45 [2] 37 5f [2] 29 42 [2] 2b 43 [2] 30 45 [2] 2c 42 [2] 30 6d }

  condition:
    any of them
}