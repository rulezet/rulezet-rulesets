rule TTP_XOR_QUAD_CurrentVersionRun_d4b6 {
  strings:
    $key_d4b6 = { 87 d9 [2] a3 d7 [2] 88 fb [2] a6 d9 [2] b2 c2 [2] bd d8 [2] a3 c5 [2] a1 c4 [2] ba c2 [2] a6 c5 [2] ba ea }

  condition:
    any of them
}