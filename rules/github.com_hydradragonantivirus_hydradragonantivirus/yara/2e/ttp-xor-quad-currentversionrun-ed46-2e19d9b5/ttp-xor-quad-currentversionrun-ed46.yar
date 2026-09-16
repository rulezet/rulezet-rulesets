rule TTP_XOR_QUAD_CurrentVersionRun_ed46 {
  strings:
    $key_ed46 = { be 29 [2] 9a 27 [2] b1 0b [2] 9f 29 [2] 8b 32 [2] 84 28 [2] 9a 35 [2] 98 34 [2] 83 32 [2] 9f 35 [2] 83 1a }

  condition:
    any of them
}