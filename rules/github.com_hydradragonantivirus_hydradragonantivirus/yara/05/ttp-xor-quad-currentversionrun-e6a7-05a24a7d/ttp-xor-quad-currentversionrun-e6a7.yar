rule TTP_XOR_QUAD_CurrentVersionRun_e6a7 {
  strings:
    $key_e6a7 = { b5 c8 [2] 91 c6 [2] ba ea [2] 94 c8 [2] 80 d3 [2] 8f c9 [2] 91 d4 [2] 93 d5 [2] 88 d3 [2] 94 d4 [2] 88 fb }

  condition:
    any of them
}