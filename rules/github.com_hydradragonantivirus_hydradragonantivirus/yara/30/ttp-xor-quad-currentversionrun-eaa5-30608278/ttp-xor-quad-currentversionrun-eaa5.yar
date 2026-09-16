rule TTP_XOR_QUAD_CurrentVersionRun_eaa5 {
  strings:
    $key_eaa5 = { b9 ca [2] 9d c4 [2] b6 e8 [2] 98 ca [2] 8c d1 [2] 83 cb [2] 9d d6 [2] 9f d7 [2] 84 d1 [2] 98 d6 [2] 84 f9 }

  condition:
    any of them
}