rule TTP_XOR_QUAD_CurrentVersionRun_3777 {
  strings:
    $key_3777 = { 64 18 [2] 40 16 [2] 6b 3a [2] 45 18 [2] 51 03 [2] 5e 19 [2] 40 04 [2] 42 05 [2] 59 03 [2] 45 04 [2] 59 2b }

  condition:
    any of them
}