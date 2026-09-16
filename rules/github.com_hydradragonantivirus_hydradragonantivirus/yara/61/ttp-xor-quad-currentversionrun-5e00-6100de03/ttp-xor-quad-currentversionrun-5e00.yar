rule TTP_XOR_QUAD_CurrentVersionRun_5e00 {
  strings:
    $key_5e00 = { 0d 6f [2] 29 61 [2] 02 4d [2] 2c 6f [2] 38 74 [2] 37 6e [2] 29 73 [2] 2b 72 [2] 30 74 [2] 2c 73 [2] 30 5c }

  condition:
    any of them
}