rule TTP_XOR_QUAD_CurrentVersionRun_38b4 {
  strings:
    $key_38b4 = { 6b db [2] 4f d5 [2] 64 f9 [2] 4a db [2] 5e c0 [2] 51 da [2] 4f c7 [2] 4d c6 [2] 56 c0 [2] 4a c7 [2] 56 e8 }

  condition:
    any of them
}