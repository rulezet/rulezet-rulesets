rule TTP_XOR_QUAD_CurrentVersionRun_d05b {
  strings:
    $key_d05b = { 83 34 [2] a7 3a [2] 8c 16 [2] a2 34 [2] b6 2f [2] b9 35 [2] a7 28 [2] a5 29 [2] be 2f [2] a2 28 [2] be 07 }

  condition:
    any of them
}