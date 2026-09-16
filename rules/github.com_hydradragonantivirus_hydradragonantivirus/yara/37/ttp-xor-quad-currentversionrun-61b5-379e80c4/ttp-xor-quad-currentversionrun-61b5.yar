rule TTP_XOR_QUAD_CurrentVersionRun_61b5 {
  strings:
    $key_61b5 = { 32 da [2] 16 d4 [2] 3d f8 [2] 13 da [2] 07 c1 [2] 08 db [2] 16 c6 [2] 14 c7 [2] 0f c1 [2] 13 c6 [2] 0f e9 }

  condition:
    any of them
}