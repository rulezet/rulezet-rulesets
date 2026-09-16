rule TTP_XOR_QUAD_CurrentVersionRun_e1b9 {
  strings:
    $key_e1b9 = { b2 d6 [2] 96 d8 [2] bd f4 [2] 93 d6 [2] 87 cd [2] 88 d7 [2] 96 ca [2] 94 cb [2] 8f cd [2] 93 ca [2] 8f e5 }

  condition:
    any of them
}