rule TTP_XOR_QUAD_CurrentVersionRun_14b8 {
  strings:
    $key_14b8 = { 47 d7 [2] 63 d9 [2] 48 f5 [2] 66 d7 [2] 72 cc [2] 7d d6 [2] 63 cb [2] 61 ca [2] 7a cc [2] 66 cb [2] 7a e4 }

  condition:
    any of them
}