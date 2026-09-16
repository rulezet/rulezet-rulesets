rule TTP_XOR_QUAD_CurrentVersionRun_2eb9 {
  strings:
    $key_2eb9 = { 7d d6 [2] 59 d8 [2] 72 f4 [2] 5c d6 [2] 48 cd [2] 47 d7 [2] 59 ca [2] 5b cb [2] 40 cd [2] 5c ca [2] 40 e5 }

  condition:
    any of them
}