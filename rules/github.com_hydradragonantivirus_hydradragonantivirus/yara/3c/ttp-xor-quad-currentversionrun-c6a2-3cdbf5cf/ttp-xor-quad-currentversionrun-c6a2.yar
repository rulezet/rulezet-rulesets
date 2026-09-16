rule TTP_XOR_QUAD_CurrentVersionRun_c6a2 {
  strings:
    $key_c6a2 = { 95 cd [2] b1 c3 [2] 9a ef [2] b4 cd [2] a0 d6 [2] af cc [2] b1 d1 [2] b3 d0 [2] a8 d6 [2] b4 d1 [2] a8 fe }

  condition:
    any of them
}