rule TTP_XOR_QUAD_CurrentVersionRun_05a5 {
  strings:
    $key_05a5 = { 56 ca [2] 72 c4 [2] 59 e8 [2] 77 ca [2] 63 d1 [2] 6c cb [2] 72 d6 [2] 70 d7 [2] 6b d1 [2] 77 d6 [2] 6b f9 }

  condition:
    any of them
}