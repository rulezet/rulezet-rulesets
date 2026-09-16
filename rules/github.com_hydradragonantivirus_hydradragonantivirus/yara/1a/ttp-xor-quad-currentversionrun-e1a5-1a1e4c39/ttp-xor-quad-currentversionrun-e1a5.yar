rule TTP_XOR_QUAD_CurrentVersionRun_e1a5 {
  strings:
    $key_e1a5 = { b2 ca [2] 96 c4 [2] bd e8 [2] 93 ca [2] 87 d1 [2] 88 cb [2] 96 d6 [2] 94 d7 [2] 8f d1 [2] 93 d6 [2] 8f f9 }

  condition:
    any of them
}