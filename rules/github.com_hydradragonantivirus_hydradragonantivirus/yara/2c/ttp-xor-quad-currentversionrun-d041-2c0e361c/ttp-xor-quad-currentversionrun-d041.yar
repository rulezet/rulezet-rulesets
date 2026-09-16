rule TTP_XOR_QUAD_CurrentVersionRun_d041 {
  strings:
    $key_d041 = { 83 2e [2] a7 20 [2] 8c 0c [2] a2 2e [2] b6 35 [2] b9 2f [2] a7 32 [2] a5 33 [2] be 35 [2] a2 32 [2] be 1d }

  condition:
    any of them
}