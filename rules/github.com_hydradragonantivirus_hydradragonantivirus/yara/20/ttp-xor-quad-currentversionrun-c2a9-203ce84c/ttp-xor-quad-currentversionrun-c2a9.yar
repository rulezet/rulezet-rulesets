rule TTP_XOR_QUAD_CurrentVersionRun_c2a9 {
  strings:
    $key_c2a9 = { 91 c6 [2] b5 c8 [2] 9e e4 [2] b0 c6 [2] a4 dd [2] ab c7 [2] b5 da [2] b7 db [2] ac dd [2] b0 da [2] ac f5 }

  condition:
    any of them
}