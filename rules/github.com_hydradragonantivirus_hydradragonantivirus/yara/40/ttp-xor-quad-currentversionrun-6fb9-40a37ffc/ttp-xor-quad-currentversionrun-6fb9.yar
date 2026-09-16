rule TTP_XOR_QUAD_CurrentVersionRun_6fb9 {
  strings:
    $key_6fb9 = { 3c d6 [2] 18 d8 [2] 33 f4 [2] 1d d6 [2] 09 cd [2] 06 d7 [2] 18 ca [2] 1a cb [2] 01 cd [2] 1d ca [2] 01 e5 }

  condition:
    any of them
}