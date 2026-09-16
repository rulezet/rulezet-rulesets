rule TTP_XOR_QUAD_CurrentVersionRun_c7b4 {
  strings:
    $key_c7b4 = { 94 db [2] b0 d5 [2] 9b f9 [2] b5 db [2] a1 c0 [2] ae da [2] b0 c7 [2] b2 c6 [2] a9 c0 [2] b5 c7 [2] a9 e8 }

  condition:
    any of them
}