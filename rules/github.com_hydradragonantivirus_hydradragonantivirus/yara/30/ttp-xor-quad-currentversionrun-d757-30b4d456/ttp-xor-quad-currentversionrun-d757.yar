rule TTP_XOR_QUAD_CurrentVersionRun_d757 {
  strings:
    $key_d757 = { 84 38 [2] a0 36 [2] 8b 1a [2] a5 38 [2] b1 23 [2] be 39 [2] a0 24 [2] a2 25 [2] b9 23 [2] a5 24 [2] b9 0b }

  condition:
    any of them
}