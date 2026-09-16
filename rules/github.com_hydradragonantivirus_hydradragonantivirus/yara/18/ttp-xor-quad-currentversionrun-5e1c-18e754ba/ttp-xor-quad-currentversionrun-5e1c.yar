rule TTP_XOR_QUAD_CurrentVersionRun_5e1c {
  strings:
    $key_5e1c = { 0d 73 [2] 29 7d [2] 02 51 [2] 2c 73 [2] 38 68 [2] 37 72 [2] 29 6f [2] 2b 6e [2] 30 68 [2] 2c 6f [2] 30 40 }

  condition:
    any of them
}