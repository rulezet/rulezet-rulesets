rule TTP_XOR_QUAD_CurrentVersionRun_c6f7 {
  strings:
    $key_c6f7 = { 95 98 [2] b1 96 [2] 9a ba [2] b4 98 [2] a0 83 [2] af 99 [2] b1 84 [2] b3 85 [2] a8 83 [2] b4 84 [2] a8 ab }

  condition:
    any of them
}