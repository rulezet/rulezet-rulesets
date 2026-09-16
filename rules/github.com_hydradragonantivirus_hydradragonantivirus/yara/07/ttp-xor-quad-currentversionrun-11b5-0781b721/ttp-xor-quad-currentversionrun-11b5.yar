rule TTP_XOR_QUAD_CurrentVersionRun_11b5 {
  strings:
    $key_11b5 = { 42 da [2] 66 d4 [2] 4d f8 [2] 63 da [2] 77 c1 [2] 78 db [2] 66 c6 [2] 64 c7 [2] 7f c1 [2] 63 c6 [2] 7f e9 }

  condition:
    any of them
}