rule TTP_XOR_QUAD_CurrentVersionRun_c2a8 {
  strings:
    $key_c2a8 = { 91 c7 [2] b5 c9 [2] 9e e5 [2] b0 c7 [2] a4 dc [2] ab c6 [2] b5 db [2] b7 da [2] ac dc [2] b0 db [2] ac f4 }

  condition:
    any of them
}