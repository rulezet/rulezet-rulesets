rule TTP_XOR_QUAD_CurrentVersionRun_edb4 {
  strings:
    $key_edb4 = { be db [2] 9a d5 [2] b1 f9 [2] 9f db [2] 8b c0 [2] 84 da [2] 9a c7 [2] 98 c6 [2] 83 c0 [2] 9f c7 [2] 83 e8 }

  condition:
    any of them
}