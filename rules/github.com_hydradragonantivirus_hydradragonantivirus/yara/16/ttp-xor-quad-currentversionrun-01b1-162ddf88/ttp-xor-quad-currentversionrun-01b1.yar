rule TTP_XOR_QUAD_CurrentVersionRun_01b1 {
  strings:
    $key_01b1 = { 52 de [2] 76 d0 [2] 5d fc [2] 73 de [2] 67 c5 [2] 68 df [2] 76 c2 [2] 74 c3 [2] 6f c5 [2] 73 c2 [2] 6f ed }

  condition:
    any of them
}