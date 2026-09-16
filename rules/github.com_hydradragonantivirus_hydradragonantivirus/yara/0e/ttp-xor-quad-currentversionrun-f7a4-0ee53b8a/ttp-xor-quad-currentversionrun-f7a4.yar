rule TTP_XOR_QUAD_CurrentVersionRun_f7a4 {
  strings:
    $key_f7a4 = { a4 cb [2] 80 c5 [2] ab e9 [2] 85 cb [2] 91 d0 [2] 9e ca [2] 80 d7 [2] 82 d6 [2] 99 d0 [2] 85 d7 [2] 99 f8 }

  condition:
    any of them
}