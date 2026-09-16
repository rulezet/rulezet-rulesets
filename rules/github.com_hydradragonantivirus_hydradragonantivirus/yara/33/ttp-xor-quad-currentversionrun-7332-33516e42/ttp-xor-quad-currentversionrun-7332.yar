rule TTP_XOR_QUAD_CurrentVersionRun_7332 {
  strings:
    $key_7332 = { 20 5d [2] 04 53 [2] 2f 7f [2] 01 5d [2] 15 46 [2] 1a 5c [2] 04 41 [2] 06 40 [2] 1d 46 [2] 01 41 [2] 1d 6e }

  condition:
    any of them
}