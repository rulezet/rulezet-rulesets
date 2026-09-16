rule TTP_XOR_QUAD_CurrentVersionRun_61b4 {
  strings:
    $key_61b4 = { 32 db [2] 16 d5 [2] 3d f9 [2] 13 db [2] 07 c0 [2] 08 da [2] 16 c7 [2] 14 c6 [2] 0f c0 [2] 13 c7 [2] 0f e8 }

  condition:
    any of them
}