rule TTP_XOR_QUAD_CurrentVersionRun_eaa4 {
  strings:
    $key_eaa4 = { b9 cb [2] 9d c5 [2] b6 e9 [2] 98 cb [2] 8c d0 [2] 83 ca [2] 9d d7 [2] 9f d6 [2] 84 d0 [2] 98 d7 [2] 84 f8 }

  condition:
    any of them
}