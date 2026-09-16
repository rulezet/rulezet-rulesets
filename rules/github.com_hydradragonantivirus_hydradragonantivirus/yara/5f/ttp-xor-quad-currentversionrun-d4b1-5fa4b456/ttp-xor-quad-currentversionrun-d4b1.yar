rule TTP_XOR_QUAD_CurrentVersionRun_d4b1 {
  strings:
    $key_d4b1 = { 87 de [2] a3 d0 [2] 88 fc [2] a6 de [2] b2 c5 [2] bd df [2] a3 c2 [2] a1 c3 [2] ba c5 [2] a6 c2 [2] ba ed }

  condition:
    any of them
}