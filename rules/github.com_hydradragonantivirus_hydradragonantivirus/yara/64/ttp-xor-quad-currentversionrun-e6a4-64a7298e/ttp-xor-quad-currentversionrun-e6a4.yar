rule TTP_XOR_QUAD_CurrentVersionRun_e6a4 {
  strings:
    $key_e6a4 = { b5 cb [2] 91 c5 [2] ba e9 [2] 94 cb [2] 80 d0 [2] 8f ca [2] 91 d7 [2] 93 d6 [2] 88 d0 [2] 94 d7 [2] 88 f8 }

  condition:
    any of them
}