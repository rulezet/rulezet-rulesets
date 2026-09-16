rule TTP_XOR_QUAD_CurrentVersionRun_5e20 {
  strings:
    $key_5e20 = { 0d 4f [2] 29 41 [2] 02 6d [2] 2c 4f [2] 38 54 [2] 37 4e [2] 29 53 [2] 2b 52 [2] 30 54 [2] 2c 53 [2] 30 7c }

  condition:
    any of them
}