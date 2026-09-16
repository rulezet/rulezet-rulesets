rule TTP_XOR_QUAD_CurrentVersionRun_427a {
  strings:
    $key_427a = { 11 15 [2] 35 1b [2] 1e 37 [2] 30 15 [2] 24 0e [2] 2b 14 [2] 35 09 [2] 37 08 [2] 2c 0e [2] 30 09 [2] 2c 26 }

  condition:
    any of them
}