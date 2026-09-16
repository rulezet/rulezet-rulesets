rule TTP_XOR_QUAD_CurrentVersionRun_0772 {
  strings:
    $key_0772 = { 54 1d [2] 70 13 [2] 5b 3f [2] 75 1d [2] 61 06 [2] 6e 1c [2] 70 01 [2] 72 00 [2] 69 06 [2] 75 01 [2] 69 2e }

  condition:
    any of them
}