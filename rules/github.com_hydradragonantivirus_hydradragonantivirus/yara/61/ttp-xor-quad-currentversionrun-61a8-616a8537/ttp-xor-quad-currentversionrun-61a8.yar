rule TTP_XOR_QUAD_CurrentVersionRun_61a8 {
  strings:
    $key_61a8 = { 32 c7 [2] 16 c9 [2] 3d e5 [2] 13 c7 [2] 07 dc [2] 08 c6 [2] 16 db [2] 14 da [2] 0f dc [2] 13 db [2] 0f f4 }

  condition:
    any of them
}