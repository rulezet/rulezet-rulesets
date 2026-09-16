rule TTP_XOR_QUAD_CurrentVersionRun_d072 {
  strings:
    $key_d072 = { 83 1d [2] a7 13 [2] 8c 3f [2] a2 1d [2] b6 06 [2] b9 1c [2] a7 01 [2] a5 00 [2] be 06 [2] a2 01 [2] be 2e }

  condition:
    any of them
}