rule TTP_XOR_QUAD_CurrentVersionRun_6196 {
  strings:
    $key_6196 = { 32 f9 [2] 16 f7 [2] 3d db [2] 13 f9 [2] 07 e2 [2] 08 f8 [2] 16 e5 [2] 14 e4 [2] 0f e2 [2] 13 e5 [2] 0f ca }

  condition:
    any of them
}