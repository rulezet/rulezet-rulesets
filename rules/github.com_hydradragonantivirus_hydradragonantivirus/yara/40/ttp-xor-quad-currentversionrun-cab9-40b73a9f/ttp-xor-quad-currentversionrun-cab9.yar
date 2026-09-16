rule TTP_XOR_QUAD_CurrentVersionRun_cab9 {
  strings:
    $key_cab9 = { 99 d6 [2] bd d8 [2] 96 f4 [2] b8 d6 [2] ac cd [2] a3 d7 [2] bd ca [2] bf cb [2] a4 cd [2] b8 ca [2] a4 e5 }

  condition:
    any of them
}