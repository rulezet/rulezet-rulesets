rule TTP_XOR_QUAD_CurrentVersionRun_d4b9 {
  strings:
    $key_d4b9 = { 87 d6 [2] a3 d8 [2] 88 f4 [2] a6 d6 [2] b2 cd [2] bd d7 [2] a3 ca [2] a1 cb [2] ba cd [2] a6 ca [2] ba e5 }

  condition:
    any of them
}