rule TTP_XOR_QUAD_CurrentVersionRun_4d32 {
  strings:
    $key_4d32 = { 1e 5d [2] 3a 53 [2] 11 7f [2] 3f 5d [2] 2b 46 [2] 24 5c [2] 3a 41 [2] 38 40 [2] 23 46 [2] 3f 41 [2] 23 6e }

  condition:
    any of them
}