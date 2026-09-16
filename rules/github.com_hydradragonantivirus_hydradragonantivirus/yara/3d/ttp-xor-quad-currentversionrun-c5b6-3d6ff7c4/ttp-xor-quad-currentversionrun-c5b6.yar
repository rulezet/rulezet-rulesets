rule TTP_XOR_QUAD_CurrentVersionRun_c5b6 {
  strings:
    $key_c5b6 = { 96 d9 [2] b2 d7 [2] 99 fb [2] b7 d9 [2] a3 c2 [2] ac d8 [2] b2 c5 [2] b0 c4 [2] ab c2 [2] b7 c5 [2] ab ea }

  condition:
    any of them
}