rule TTP_XOR_QUAD_CurrentVersionRun_c141 {
  strings:
    $key_c141 = { 92 2e [2] b6 20 [2] 9d 0c [2] b3 2e [2] a7 35 [2] a8 2f [2] b6 32 [2] b4 33 [2] af 35 [2] b3 32 [2] af 1d }

  condition:
    any of them
}