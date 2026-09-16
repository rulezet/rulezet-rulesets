rule TTP_XOR_QUAD_CurrentVersionRun_7eb9 {
  strings:
    $key_7eb9 = { 2d d6 [2] 09 d8 [2] 22 f4 [2] 0c d6 [2] 18 cd [2] 17 d7 [2] 09 ca [2] 0b cb [2] 10 cd [2] 0c ca [2] 10 e5 }

  condition:
    any of them
}