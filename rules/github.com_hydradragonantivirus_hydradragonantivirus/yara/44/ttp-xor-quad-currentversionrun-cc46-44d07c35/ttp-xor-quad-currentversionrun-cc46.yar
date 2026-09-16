rule TTP_XOR_QUAD_CurrentVersionRun_cc46 {
  strings:
    $key_cc46 = { 9f 29 [2] bb 27 [2] 90 0b [2] be 29 [2] aa 32 [2] a5 28 [2] bb 35 [2] b9 34 [2] a2 32 [2] be 35 [2] a2 1a }

  condition:
    any of them
}