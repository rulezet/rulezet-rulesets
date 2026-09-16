rule TTP_XOR_QUAD_CurrentVersionRun_bba4 {
  strings:
    $key_bba4 = { e8 cb [2] cc c5 [2] e7 e9 [2] c9 cb [2] dd d0 [2] d2 ca [2] cc d7 [2] ce d6 [2] d5 d0 [2] c9 d7 [2] d5 f8 }

  condition:
    any of them
}