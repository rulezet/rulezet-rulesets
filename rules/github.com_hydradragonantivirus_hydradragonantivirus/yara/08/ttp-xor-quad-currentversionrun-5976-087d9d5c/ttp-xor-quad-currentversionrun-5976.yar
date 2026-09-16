rule TTP_XOR_QUAD_CurrentVersionRun_5976 {
  strings:
    $key_5976 = { 0a 19 [2] 2e 17 [2] 05 3b [2] 2b 19 [2] 3f 02 [2] 30 18 [2] 2e 05 [2] 2c 04 [2] 37 02 [2] 2b 05 [2] 37 2a }

  condition:
    any of them
}