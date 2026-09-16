rule TTP_XOR_QUAD_CurrentVersionRun_54b4 {
  strings:
    $key_54b4 = { 07 db [2] 23 d5 [2] 08 f9 [2] 26 db [2] 32 c0 [2] 3d da [2] 23 c7 [2] 21 c6 [2] 3a c0 [2] 26 c7 [2] 3a e8 }

  condition:
    any of them
}