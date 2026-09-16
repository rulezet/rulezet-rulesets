rule TTP_XOR_QUAD_CurrentVersionRun_4032 {
  strings:
    $key_4032 = { 13 5d [2] 37 53 [2] 1c 7f [2] 32 5d [2] 26 46 [2] 29 5c [2] 37 41 [2] 35 40 [2] 2e 46 [2] 32 41 [2] 2e 6e }

  condition:
    any of them
}