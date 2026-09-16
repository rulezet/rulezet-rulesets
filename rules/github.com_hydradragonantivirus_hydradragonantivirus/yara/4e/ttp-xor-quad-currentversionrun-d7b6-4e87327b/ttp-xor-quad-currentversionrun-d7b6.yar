rule TTP_XOR_QUAD_CurrentVersionRun_d7b6 {
  strings:
    $key_d7b6 = { 84 d9 [2] a0 d7 [2] 8b fb [2] a5 d9 [2] b1 c2 [2] be d8 [2] a0 c5 [2] a2 c4 [2] b9 c2 [2] a5 c5 [2] b9 ea }

  condition:
    any of them
}