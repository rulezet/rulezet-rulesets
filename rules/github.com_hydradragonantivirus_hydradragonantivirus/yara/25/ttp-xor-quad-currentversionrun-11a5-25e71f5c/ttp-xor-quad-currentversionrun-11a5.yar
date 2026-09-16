rule TTP_XOR_QUAD_CurrentVersionRun_11a5 {
  strings:
    $key_11a5 = { 42 ca [2] 66 c4 [2] 4d e8 [2] 63 ca [2] 77 d1 [2] 78 cb [2] 66 d6 [2] 64 d7 [2] 7f d1 [2] 63 d6 [2] 7f f9 }

  condition:
    any of them
}