rule TTP_XOR_QUAD_CurrentVersionRun_e2a4 {
  strings:
    $key_e2a4 = { b1 cb [2] 95 c5 [2] be e9 [2] 90 cb [2] 84 d0 [2] 8b ca [2] 95 d7 [2] 97 d6 [2] 8c d0 [2] 90 d7 [2] 8c f8 }

  condition:
    any of them
}