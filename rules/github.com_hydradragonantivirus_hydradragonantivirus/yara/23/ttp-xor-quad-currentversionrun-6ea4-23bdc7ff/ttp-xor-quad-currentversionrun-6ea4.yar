rule TTP_XOR_QUAD_CurrentVersionRun_6ea4 {
  strings:
    $key_6ea4 = { 3d cb [2] 19 c5 [2] 32 e9 [2] 1c cb [2] 08 d0 [2] 07 ca [2] 19 d7 [2] 1b d6 [2] 00 d0 [2] 1c d7 [2] 00 f8 }

  condition:
    any of them
}