rule TTP_XOR_QUAD_CurrentVersionRun_34b8 {
  strings:
    $key_34b8 = { 67 d7 [2] 43 d9 [2] 68 f5 [2] 46 d7 [2] 52 cc [2] 5d d6 [2] 43 cb [2] 41 ca [2] 5a cc [2] 46 cb [2] 5a e4 }

  condition:
    any of them
}