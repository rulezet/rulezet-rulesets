rule TTP_XOR_QUAD_CurrentVersionRun_c3f7 {
  strings:
    $key_c3f7 = { 90 98 [2] b4 96 [2] 9f ba [2] b1 98 [2] a5 83 [2] aa 99 [2] b4 84 [2] b6 85 [2] ad 83 [2] b1 84 [2] ad ab }

  condition:
    any of them
}