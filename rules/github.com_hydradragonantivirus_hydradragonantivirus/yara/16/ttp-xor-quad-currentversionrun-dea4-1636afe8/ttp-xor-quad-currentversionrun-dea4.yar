rule TTP_XOR_QUAD_CurrentVersionRun_dea4 {
  strings:
    $key_dea4 = { 8d cb [2] a9 c5 [2] 82 e9 [2] ac cb [2] b8 d0 [2] b7 ca [2] a9 d7 [2] ab d6 [2] b0 d0 [2] ac d7 [2] b0 f8 }

  condition:
    any of them
}