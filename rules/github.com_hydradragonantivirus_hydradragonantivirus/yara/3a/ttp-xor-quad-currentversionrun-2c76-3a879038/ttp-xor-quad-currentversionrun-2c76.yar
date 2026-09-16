rule TTP_XOR_QUAD_CurrentVersionRun_2c76 {
  strings:
    $key_2c76 = { 7f 19 [2] 5b 17 [2] 70 3b [2] 5e 19 [2] 4a 02 [2] 45 18 [2] 5b 05 [2] 59 04 [2] 42 02 [2] 5e 05 [2] 42 2a }

  condition:
    any of them
}