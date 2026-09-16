rule TTP_XOR_QUAD_CurrentVersionRun_7646 {
  strings:
    $key_7646 = { 25 29 [2] 01 27 [2] 2a 0b [2] 04 29 [2] 10 32 [2] 1f 28 [2] 01 35 [2] 03 34 [2] 18 32 [2] 04 35 [2] 18 1a }

  condition:
    any of them
}