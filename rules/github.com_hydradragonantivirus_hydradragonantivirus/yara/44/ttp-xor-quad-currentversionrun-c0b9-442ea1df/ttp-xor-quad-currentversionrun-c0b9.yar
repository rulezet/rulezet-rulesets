rule TTP_XOR_QUAD_CurrentVersionRun_c0b9 {
  strings:
    $key_c0b9 = { 93 d6 [2] b7 d8 [2] 9c f4 [2] b2 d6 [2] a6 cd [2] a9 d7 [2] b7 ca [2] b5 cb [2] ae cd [2] b2 ca [2] ae e5 }

  condition:
    any of them
}