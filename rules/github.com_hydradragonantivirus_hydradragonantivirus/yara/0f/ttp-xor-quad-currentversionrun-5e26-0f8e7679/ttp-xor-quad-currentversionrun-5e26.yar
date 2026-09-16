rule TTP_XOR_QUAD_CurrentVersionRun_5e26 {
  strings:
    $key_5e26 = { 0d 49 [2] 29 47 [2] 02 6b [2] 2c 49 [2] 38 52 [2] 37 48 [2] 29 55 [2] 2b 54 [2] 30 52 [2] 2c 55 [2] 30 7a }

  condition:
    any of them
}