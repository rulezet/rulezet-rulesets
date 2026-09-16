rule TTP_XOR_QUAD_CurrentVersionRun_2172 {
  strings:
    $key_2172 = { 72 1d [2] 56 13 [2] 7d 3f [2] 53 1d [2] 47 06 [2] 48 1c [2] 56 01 [2] 54 00 [2] 4f 06 [2] 53 01 [2] 4f 2e }

  condition:
    any of them
}