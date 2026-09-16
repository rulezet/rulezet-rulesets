rule TTP_XOR_QUAD_CurrentVersionRun_3fb9 {
  strings:
    $key_3fb9 = { 6c d6 [2] 48 d8 [2] 63 f4 [2] 4d d6 [2] 59 cd [2] 56 d7 [2] 48 ca [2] 4a cb [2] 51 cd [2] 4d ca [2] 51 e5 }

  condition:
    any of them
}