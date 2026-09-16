rule TTP_XOR_QUAD_CurrentVersionRun_21b1 {
  strings:
    $key_21b1 = { 72 de [2] 56 d0 [2] 7d fc [2] 53 de [2] 47 c5 [2] 48 df [2] 56 c2 [2] 54 c3 [2] 4f c5 [2] 53 c2 [2] 4f ed }

  condition:
    any of them
}