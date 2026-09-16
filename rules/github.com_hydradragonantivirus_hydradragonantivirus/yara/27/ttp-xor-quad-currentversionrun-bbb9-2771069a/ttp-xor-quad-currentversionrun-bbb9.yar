rule TTP_XOR_QUAD_CurrentVersionRun_bbb9 {
  strings:
    $key_bbb9 = { e8 d6 [2] cc d8 [2] e7 f4 [2] c9 d6 [2] dd cd [2] d2 d7 [2] cc ca [2] ce cb [2] d5 cd [2] c9 ca [2] d5 e5 }

  condition:
    any of them
}