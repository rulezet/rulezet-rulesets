rule TTP_XOR_QUAD_CurrentVersionRun_d747 {
  strings:
    $key_d747 = { 84 28 [2] a0 26 [2] 8b 0a [2] a5 28 [2] b1 33 [2] be 29 [2] a0 34 [2] a2 35 [2] b9 33 [2] a5 34 [2] b9 1b }

  condition:
    any of them
}