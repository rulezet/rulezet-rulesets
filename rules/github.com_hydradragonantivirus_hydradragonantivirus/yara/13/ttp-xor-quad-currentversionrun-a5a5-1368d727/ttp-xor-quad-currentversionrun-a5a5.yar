rule TTP_XOR_QUAD_CurrentVersionRun_a5a5 {
  strings:
    $key_a5a5 = { f6 ca [2] d2 c4 [2] f9 e8 [2] d7 ca [2] c3 d1 [2] cc cb [2] d2 d6 [2] d0 d7 [2] cb d1 [2] d7 d6 [2] cb f9 }

  condition:
    any of them
}