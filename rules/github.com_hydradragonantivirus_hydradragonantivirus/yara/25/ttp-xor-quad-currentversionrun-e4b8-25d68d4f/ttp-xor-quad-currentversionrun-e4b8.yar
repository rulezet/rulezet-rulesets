rule TTP_XOR_QUAD_CurrentVersionRun_e4b8 {
  strings:
    $key_e4b8 = { b7 d7 [2] 93 d9 [2] b8 f5 [2] 96 d7 [2] 82 cc [2] 8d d6 [2] 93 cb [2] 91 ca [2] 8a cc [2] 96 cb [2] 8a e4 }

  condition:
    any of them
}