rule TTP_XOR_QUAD_CurrentVersionRun_7677 {
  strings:
    $key_7677 = { 25 18 [2] 01 16 [2] 2a 3a [2] 04 18 [2] 10 03 [2] 1f 19 [2] 01 04 [2] 03 05 [2] 18 03 [2] 04 04 [2] 18 2b }

  condition:
    any of them
}