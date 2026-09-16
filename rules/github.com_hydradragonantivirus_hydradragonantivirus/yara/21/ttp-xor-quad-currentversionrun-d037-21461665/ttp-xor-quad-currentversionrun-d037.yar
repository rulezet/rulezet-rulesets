rule TTP_XOR_QUAD_CurrentVersionRun_d037 {
  strings:
    $key_d037 = { 83 58 [2] a7 56 [2] 8c 7a [2] a2 58 [2] b6 43 [2] b9 59 [2] a7 44 [2] a5 45 [2] be 43 [2] a2 44 [2] be 6b }

  condition:
    any of them
}