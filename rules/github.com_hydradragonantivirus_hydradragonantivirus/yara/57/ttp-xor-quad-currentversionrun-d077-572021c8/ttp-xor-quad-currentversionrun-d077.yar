rule TTP_XOR_QUAD_CurrentVersionRun_d077 {
  strings:
    $key_d077 = { 83 18 [2] a7 16 [2] 8c 3a [2] a2 18 [2] b6 03 [2] b9 19 [2] a7 04 [2] a5 05 [2] be 03 [2] a2 04 [2] be 2b }

  condition:
    any of them
}