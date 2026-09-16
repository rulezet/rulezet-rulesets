rule TTP_XOR_QUAD_CurrentVersionRun_fcb9 {
  strings:
    $key_fcb9 = { af d6 [2] 8b d8 [2] a0 f4 [2] 8e d6 [2] 9a cd [2] 95 d7 [2] 8b ca [2] 89 cb [2] 92 cd [2] 8e ca [2] 92 e5 }

  condition:
    any of them
}