rule TTP_XOR_QUAD_CurrentVersionRun_ceb2 {
  strings:
    $key_ceb2 = { 9d dd [2] b9 d3 [2] 92 ff [2] bc dd [2] a8 c6 [2] a7 dc [2] b9 c1 [2] bb c0 [2] a0 c6 [2] bc c1 [2] a0 ee }

  condition:
    any of them
}