rule TTP_XOR_QUAD_CurrentVersionRun_01a4 {
  strings:
    $key_01a4 = { 52 cb [2] 76 c5 [2] 5d e9 [2] 73 cb [2] 67 d0 [2] 68 ca [2] 76 d7 [2] 74 d6 [2] 6f d0 [2] 73 d7 [2] 6f f8 }

  condition:
    any of them
}