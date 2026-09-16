rule TTP_XOR_QUAD_CurrentVersionRun_61b9 {
  strings:
    $key_61b9 = { 32 d6 [2] 16 d8 [2] 3d f4 [2] 13 d6 [2] 07 cd [2] 08 d7 [2] 16 ca [2] 14 cb [2] 0f cd [2] 13 ca [2] 0f e5 }

  condition:
    any of them
}