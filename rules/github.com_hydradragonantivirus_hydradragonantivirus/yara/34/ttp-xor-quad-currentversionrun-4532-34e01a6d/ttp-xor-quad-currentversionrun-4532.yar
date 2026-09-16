rule TTP_XOR_QUAD_CurrentVersionRun_4532 {
  strings:
    $key_4532 = { 16 5d [2] 32 53 [2] 19 7f [2] 37 5d [2] 23 46 [2] 2c 5c [2] 32 41 [2] 30 40 [2] 2b 46 [2] 37 41 [2] 2b 6e }

  condition:
    any of them
}