rule TTP_XOR_QUAD_CurrentVersionRun_11b4 {
  strings:
    $key_11b4 = { 42 db [2] 66 d5 [2] 4d f9 [2] 63 db [2] 77 c0 [2] 78 da [2] 66 c7 [2] 64 c6 [2] 7f c0 [2] 63 c7 [2] 7f e8 }

  condition:
    any of them
}