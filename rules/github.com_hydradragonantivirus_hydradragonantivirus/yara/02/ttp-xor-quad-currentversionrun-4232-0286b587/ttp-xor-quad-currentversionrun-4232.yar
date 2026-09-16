rule TTP_XOR_QUAD_CurrentVersionRun_4232 {
  strings:
    $key_4232 = { 11 5d [2] 35 53 [2] 1e 7f [2] 30 5d [2] 24 46 [2] 2b 5c [2] 35 41 [2] 37 40 [2] 2c 46 [2] 30 41 [2] 2c 6e }

  condition:
    any of them
}