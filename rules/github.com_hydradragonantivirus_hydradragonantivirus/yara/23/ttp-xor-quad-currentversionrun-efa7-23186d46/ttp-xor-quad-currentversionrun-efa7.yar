rule TTP_XOR_QUAD_CurrentVersionRun_efa7 {
  strings:
    $key_efa7 = { bc c8 [2] 98 c6 [2] b3 ea [2] 9d c8 [2] 89 d3 [2] 86 c9 [2] 98 d4 [2] 9a d5 [2] 81 d3 [2] 9d d4 [2] 81 fb }

  condition:
    any of them
}