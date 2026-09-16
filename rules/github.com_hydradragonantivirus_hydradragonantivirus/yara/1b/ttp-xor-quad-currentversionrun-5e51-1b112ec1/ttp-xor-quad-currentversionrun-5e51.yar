rule TTP_XOR_QUAD_CurrentVersionRun_5e51 {
  strings:
    $key_5e51 = { 0d 3e [2] 29 30 [2] 02 1c [2] 2c 3e [2] 38 25 [2] 37 3f [2] 29 22 [2] 2b 23 [2] 30 25 [2] 2c 22 [2] 30 0d }

  condition:
    any of them
}