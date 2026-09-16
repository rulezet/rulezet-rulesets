rule TTP_XOR_QUAD_CurrentVersionRun_5926 {
  strings:
    $key_5926 = { 0a 49 [2] 2e 47 [2] 05 6b [2] 2b 49 [2] 3f 52 [2] 30 48 [2] 2e 55 [2] 2c 54 [2] 37 52 [2] 2b 55 [2] 37 7a }

  condition:
    any of them
}