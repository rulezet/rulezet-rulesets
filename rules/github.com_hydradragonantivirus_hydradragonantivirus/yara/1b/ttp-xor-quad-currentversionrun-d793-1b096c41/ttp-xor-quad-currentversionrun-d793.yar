rule TTP_XOR_QUAD_CurrentVersionRun_d793 {
  strings:
    $key_d793 = { 84 fc [2] a0 f2 [2] 8b de [2] a5 fc [2] b1 e7 [2] be fd [2] a0 e0 [2] a2 e1 [2] b9 e7 [2] a5 e0 [2] b9 cf }

  condition:
    any of them
}