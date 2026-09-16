rule TTP_XOR_QUAD_CurrentVersionRun_61b6 {
  strings:
    $key_61b6 = { 32 d9 [2] 16 d7 [2] 3d fb [2] 13 d9 [2] 07 c2 [2] 08 d8 [2] 16 c5 [2] 14 c4 [2] 0f c2 [2] 13 c5 [2] 0f ea }

  condition:
    any of them
}