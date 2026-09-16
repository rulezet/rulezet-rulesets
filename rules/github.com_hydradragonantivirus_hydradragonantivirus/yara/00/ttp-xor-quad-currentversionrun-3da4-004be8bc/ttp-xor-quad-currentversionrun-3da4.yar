rule TTP_XOR_QUAD_CurrentVersionRun_3da4 {
  strings:
    $key_3da4 = { 6e cb [2] 4a c5 [2] 61 e9 [2] 4f cb [2] 5b d0 [2] 54 ca [2] 4a d7 [2] 48 d6 [2] 53 d0 [2] 4f d7 [2] 53 f8 }

  condition:
    any of them
}