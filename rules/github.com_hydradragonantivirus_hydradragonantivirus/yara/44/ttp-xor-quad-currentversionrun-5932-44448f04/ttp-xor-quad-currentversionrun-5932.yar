rule TTP_XOR_QUAD_CurrentVersionRun_5932 {
  strings:
    $key_5932 = { 0a 5d [2] 2e 53 [2] 05 7f [2] 2b 5d [2] 3f 46 [2] 30 5c [2] 2e 41 [2] 2c 40 [2] 37 46 [2] 2b 41 [2] 37 6e }

  condition:
    any of them
}