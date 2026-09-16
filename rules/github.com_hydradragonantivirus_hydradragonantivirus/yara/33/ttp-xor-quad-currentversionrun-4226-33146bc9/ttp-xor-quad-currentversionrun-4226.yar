rule TTP_XOR_QUAD_CurrentVersionRun_4226 {
  strings:
    $key_4226 = { 11 49 [2] 35 47 [2] 1e 6b [2] 30 49 [2] 24 52 [2] 2b 48 [2] 35 55 [2] 37 54 [2] 2c 52 [2] 30 55 [2] 2c 7a }

  condition:
    any of them
}