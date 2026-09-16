rule TTP_XOR_QUAD_CurrentVersionRun_91a4 {
  strings:
    $key_91a4 = { c2 cb [2] e6 c5 [2] cd e9 [2] e3 cb [2] f7 d0 [2] f8 ca [2] e6 d7 [2] e4 d6 [2] ff d0 [2] e3 d7 [2] ff f8 }

  condition:
    any of them
}