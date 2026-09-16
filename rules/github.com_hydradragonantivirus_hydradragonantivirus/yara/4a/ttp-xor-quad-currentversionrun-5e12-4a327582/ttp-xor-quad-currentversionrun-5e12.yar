rule TTP_XOR_QUAD_CurrentVersionRun_5e12 {
  strings:
    $key_5e12 = { 0d 7d [2] 29 73 [2] 02 5f [2] 2c 7d [2] 38 66 [2] 37 7c [2] 29 61 [2] 2b 60 [2] 30 66 [2] 2c 61 [2] 30 4e }

  condition:
    any of them
}