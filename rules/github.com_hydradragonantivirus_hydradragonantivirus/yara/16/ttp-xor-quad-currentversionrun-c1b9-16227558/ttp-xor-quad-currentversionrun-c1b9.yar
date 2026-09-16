rule TTP_XOR_QUAD_CurrentVersionRun_c1b9 {
  strings:
    $key_c1b9 = { 92 d6 [2] b6 d8 [2] 9d f4 [2] b3 d6 [2] a7 cd [2] a8 d7 [2] b6 ca [2] b4 cb [2] af cd [2] b3 ca [2] af e5 }

  condition:
    any of them
}