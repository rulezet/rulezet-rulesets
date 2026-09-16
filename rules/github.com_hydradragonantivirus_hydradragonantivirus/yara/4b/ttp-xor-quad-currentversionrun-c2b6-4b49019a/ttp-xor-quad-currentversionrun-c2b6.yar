rule TTP_XOR_QUAD_CurrentVersionRun_c2b6 {
  strings:
    $key_c2b6 = { 91 d9 [2] b5 d7 [2] 9e fb [2] b0 d9 [2] a4 c2 [2] ab d8 [2] b5 c5 [2] b7 c4 [2] ac c2 [2] b0 c5 [2] ac ea }

  condition:
    any of them
}