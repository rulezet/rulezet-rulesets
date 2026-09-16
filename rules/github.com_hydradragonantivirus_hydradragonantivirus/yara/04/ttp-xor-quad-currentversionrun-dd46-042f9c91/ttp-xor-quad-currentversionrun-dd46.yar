rule TTP_XOR_QUAD_CurrentVersionRun_dd46 {
  strings:
    $key_dd46 = { 8e 29 [2] aa 27 [2] 81 0b [2] af 29 [2] bb 32 [2] b4 28 [2] aa 35 [2] a8 34 [2] b3 32 [2] af 35 [2] b3 1a }

  condition:
    any of them
}