rule TTP_XOR_QUAD_CurrentVersionRun_4220 {
  strings:
    $key_4220 = { 11 4f [2] 35 41 [2] 1e 6d [2] 30 4f [2] 24 54 [2] 2b 4e [2] 35 53 [2] 37 52 [2] 2c 54 [2] 30 53 [2] 2c 7c }

  condition:
    any of them
}