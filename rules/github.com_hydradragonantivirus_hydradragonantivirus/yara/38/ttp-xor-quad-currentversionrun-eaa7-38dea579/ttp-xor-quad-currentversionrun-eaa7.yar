rule TTP_XOR_QUAD_CurrentVersionRun_eaa7 {
  strings:
    $key_eaa7 = { b9 c8 [2] 9d c6 [2] b6 ea [2] 98 c8 [2] 8c d3 [2] 83 c9 [2] 9d d4 [2] 9f d5 [2] 84 d3 [2] 98 d4 [2] 84 fb }

  condition:
    any of them
}