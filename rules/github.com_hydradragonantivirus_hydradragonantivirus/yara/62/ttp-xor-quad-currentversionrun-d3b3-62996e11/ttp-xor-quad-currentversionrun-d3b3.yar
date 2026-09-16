rule TTP_XOR_QUAD_CurrentVersionRun_d3b3 {
  strings:
    $key_d3b3 = { 80 dc [2] a4 d2 [2] 8f fe [2] a1 dc [2] b5 c7 [2] ba dd [2] a4 c0 [2] a6 c1 [2] bd c7 [2] a1 c0 [2] bd ef }

  condition:
    any of them
}