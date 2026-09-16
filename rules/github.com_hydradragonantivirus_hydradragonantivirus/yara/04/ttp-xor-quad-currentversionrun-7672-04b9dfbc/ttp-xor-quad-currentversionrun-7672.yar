rule TTP_XOR_QUAD_CurrentVersionRun_7672 {
  strings:
    $key_7672 = { 25 1d [2] 01 13 [2] 2a 3f [2] 04 1d [2] 10 06 [2] 1f 1c [2] 01 01 [2] 03 00 [2] 18 06 [2] 04 01 [2] 18 2e }

  condition:
    any of them
}