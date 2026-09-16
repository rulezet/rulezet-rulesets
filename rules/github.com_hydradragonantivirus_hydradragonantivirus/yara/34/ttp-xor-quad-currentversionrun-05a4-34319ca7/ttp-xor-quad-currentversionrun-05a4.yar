rule TTP_XOR_QUAD_CurrentVersionRun_05a4 {
  strings:
    $key_05a4 = { 56 cb [2] 72 c5 [2] 59 e9 [2] 77 cb [2] 63 d0 [2] 6c ca [2] 72 d7 [2] 70 d6 [2] 6b d0 [2] 77 d7 [2] 6b f8 }

  condition:
    any of them
}