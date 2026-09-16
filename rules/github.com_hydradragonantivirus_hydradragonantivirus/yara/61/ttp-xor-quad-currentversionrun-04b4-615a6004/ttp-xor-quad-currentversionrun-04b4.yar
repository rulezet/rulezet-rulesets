rule TTP_XOR_QUAD_CurrentVersionRun_04b4 {
  strings:
    $key_04b4 = { 57 db [2] 73 d5 [2] 58 f9 [2] 76 db [2] 62 c0 [2] 6d da [2] 73 c7 [2] 71 c6 [2] 6a c0 [2] 76 c7 [2] 6a e8 }

  condition:
    any of them
}