rule TTP_XOR_QUAD_CurrentVersionRun_e4b5 {
  strings:
    $key_e4b5 = { b7 da [2] 93 d4 [2] b8 f8 [2] 96 da [2] 82 c1 [2] 8d db [2] 93 c6 [2] 91 c7 [2] 8a c1 [2] 96 c6 [2] 8a e9 }

  condition:
    any of them
}