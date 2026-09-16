rule TTP_XOR_QUAD_CurrentVersionRun_e1a4 {
  strings:
    $key_e1a4 = { b2 cb [2] 96 c5 [2] bd e9 [2] 93 cb [2] 87 d0 [2] 88 ca [2] 96 d7 [2] 94 d6 [2] 8f d0 [2] 93 d7 [2] 8f f8 }

  condition:
    any of them
}