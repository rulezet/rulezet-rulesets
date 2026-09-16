rule TTP_XOR_QUAD_CurrentVersionRun_72d3 {
  strings:
    $key_72d3 = { 21 bc [2] 05 b2 [2] 2e 9e [2] 00 bc [2] 14 a7 [2] 1b bd [2] 05 a0 [2] 07 a1 [2] 1c a7 [2] 00 a0 [2] 1c 8f }

  condition:
    any of them
}