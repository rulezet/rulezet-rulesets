rule TTP_XOR_QUAD_CurrentVersionRun_d777 {
  strings:
    $key_d777 = { 84 18 [2] a0 16 [2] 8b 3a [2] a5 18 [2] b1 03 [2] be 19 [2] a0 04 [2] a2 05 [2] b9 03 [2] a5 04 [2] b9 2b }

  condition:
    any of them
}