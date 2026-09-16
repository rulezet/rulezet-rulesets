rule TTP_XOR_QUAD_CurrentVersionRun_61a4 {
  strings:
    $key_61a4 = { 32 cb [2] 16 c5 [2] 3d e9 [2] 13 cb [2] 07 d0 [2] 08 ca [2] 16 d7 [2] 14 d6 [2] 0f d0 [2] 13 d7 [2] 0f f8 }

  condition:
    any of them
}