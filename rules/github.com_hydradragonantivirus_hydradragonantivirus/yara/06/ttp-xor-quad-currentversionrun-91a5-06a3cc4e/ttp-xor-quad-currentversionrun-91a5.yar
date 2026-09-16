rule TTP_XOR_QUAD_CurrentVersionRun_91a5 {
  strings:
    $key_91a5 = { c2 ca [2] e6 c4 [2] cd e8 [2] e3 ca [2] f7 d1 [2] f8 cb [2] e6 d6 [2] e4 d7 [2] ff d1 [2] e3 d6 [2] ff f9 }

  condition:
    any of them
}