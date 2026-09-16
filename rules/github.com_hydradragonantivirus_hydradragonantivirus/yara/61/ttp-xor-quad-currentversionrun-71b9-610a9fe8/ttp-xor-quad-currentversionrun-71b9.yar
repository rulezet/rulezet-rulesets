rule TTP_XOR_QUAD_CurrentVersionRun_71b9 {
  strings:
    $key_71b9 = { 22 d6 [2] 06 d8 [2] 2d f4 [2] 03 d6 [2] 17 cd [2] 18 d7 [2] 06 ca [2] 04 cb [2] 1f cd [2] 03 ca [2] 1f e5 }

  condition:
    any of them
}