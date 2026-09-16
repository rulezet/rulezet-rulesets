rule TTP_XOR_QUAD_CurrentVersionRun_0fb9 {
  strings:
    $key_0fb9 = { 5c d6 [2] 78 d8 [2] 53 f4 [2] 7d d6 [2] 69 cd [2] 66 d7 [2] 78 ca [2] 7a cb [2] 61 cd [2] 7d ca [2] 61 e5 }

  condition:
    any of them
}