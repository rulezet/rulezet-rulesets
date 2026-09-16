rule TTP_XOR_QUAD_CurrentVersionRun_dfb9 {
  strings:
    $key_dfb9 = { 8c d6 [2] a8 d8 [2] 83 f4 [2] ad d6 [2] b9 cd [2] b6 d7 [2] a8 ca [2] aa cb [2] b1 cd [2] ad ca [2] b1 e5 }

  condition:
    any of them
}