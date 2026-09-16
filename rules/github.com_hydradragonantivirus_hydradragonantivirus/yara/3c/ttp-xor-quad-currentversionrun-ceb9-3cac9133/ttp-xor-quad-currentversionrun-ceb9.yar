rule TTP_XOR_QUAD_CurrentVersionRun_ceb9 {
  strings:
    $key_ceb9 = { 9d d6 [2] b9 d8 [2] 92 f4 [2] bc d6 [2] a8 cd [2] a7 d7 [2] b9 ca [2] bb cb [2] a0 cd [2] bc ca [2] a0 e5 }

  condition:
    any of them
}