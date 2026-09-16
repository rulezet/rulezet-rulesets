rule TTP_XOR_QUAD_CurrentVersionRun_44b4 {
  strings:
    $key_44b4 = { 17 db [2] 33 d5 [2] 18 f9 [2] 36 db [2] 22 c0 [2] 2d da [2] 33 c7 [2] 31 c6 [2] 2a c0 [2] 36 c7 [2] 2a e8 }

  condition:
    any of them
}