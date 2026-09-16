rule TTP_XOR_QUAD_CurrentVersionRun_eeb9 {
  strings:
    $key_eeb9 = { bd d6 [2] 99 d8 [2] b2 f4 [2] 9c d6 [2] 88 cd [2] 87 d7 [2] 99 ca [2] 9b cb [2] 80 cd [2] 9c ca [2] 80 e5 }

  condition:
    any of them
}