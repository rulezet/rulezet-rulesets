rule TTP_XOR_QUAD_CurrentVersionRun_d707 {
  strings:
    $key_d707 = { 84 68 [2] a0 66 [2] 8b 4a [2] a5 68 [2] b1 73 [2] be 69 [2] a0 74 [2] a2 75 [2] b9 73 [2] a5 74 [2] b9 5b }

  condition:
    any of them
}