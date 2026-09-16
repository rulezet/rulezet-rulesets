rule TTP_XOR_QUAD_CurrentVersionRun_e1b1 {
  strings:
    $key_e1b1 = { b2 de [2] 96 d0 [2] bd fc [2] 93 de [2] 87 c5 [2] 88 df [2] 96 c2 [2] 94 c3 [2] 8f c5 [2] 93 c2 [2] 8f ed }

  condition:
    any of them
}