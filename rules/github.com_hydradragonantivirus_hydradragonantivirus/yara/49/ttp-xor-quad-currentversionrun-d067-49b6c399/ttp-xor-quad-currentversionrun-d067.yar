rule TTP_XOR_QUAD_CurrentVersionRun_d067 {
  strings:
    $key_d067 = { 83 08 [2] a7 06 [2] 8c 2a [2] a2 08 [2] b6 13 [2] b9 09 [2] a7 14 [2] a5 15 [2] be 13 [2] a2 14 [2] be 3b }

  condition:
    any of them
}