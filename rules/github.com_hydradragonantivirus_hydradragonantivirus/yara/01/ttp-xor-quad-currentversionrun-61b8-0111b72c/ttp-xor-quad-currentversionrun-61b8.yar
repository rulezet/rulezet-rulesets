rule TTP_XOR_QUAD_CurrentVersionRun_61b8 {
  strings:
    $key_61b8 = { 32 d7 [2] 16 d9 [2] 3d f5 [2] 13 d7 [2] 07 cc [2] 08 d6 [2] 16 cb [2] 14 ca [2] 0f cc [2] 13 cb [2] 0f e4 }

  condition:
    any of them
}