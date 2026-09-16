rule TTP_XOR_QUAD_CurrentVersionRun_2fb9 {
  strings:
    $key_2fb9 = { 7c d6 [2] 58 d8 [2] 73 f4 [2] 5d d6 [2] 49 cd [2] 46 d7 [2] 58 ca [2] 5a cb [2] 41 cd [2] 5d ca [2] 41 e5 }

  condition:
    any of them
}