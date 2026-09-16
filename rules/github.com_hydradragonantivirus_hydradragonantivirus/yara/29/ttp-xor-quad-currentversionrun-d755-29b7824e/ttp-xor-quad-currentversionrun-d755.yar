rule TTP_XOR_QUAD_CurrentVersionRun_d755 {
  strings:
    $key_d755 = { 84 3a [2] a0 34 [2] 8b 18 [2] a5 3a [2] b1 21 [2] be 3b [2] a0 26 [2] a2 27 [2] b9 21 [2] a5 26 [2] b9 09 }

  condition:
    any of them
}