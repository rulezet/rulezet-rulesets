rule TTP_XOR_QUAD_CurrentVersionRun_3572 {
  strings:
    $key_3572 = { 66 1d [2] 42 13 [2] 69 3f [2] 47 1d [2] 53 06 [2] 5c 1c [2] 42 01 [2] 40 00 [2] 5b 06 [2] 47 01 [2] 5b 2e }

  condition:
    any of them
}