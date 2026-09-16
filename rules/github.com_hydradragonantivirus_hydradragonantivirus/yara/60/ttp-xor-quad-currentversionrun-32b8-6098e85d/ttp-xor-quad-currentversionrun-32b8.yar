rule TTP_XOR_QUAD_CurrentVersionRun_32b8 {
  strings:
    $key_32b8 = { 61 d7 [2] 45 d9 [2] 6e f5 [2] 40 d7 [2] 54 cc [2] 5b d6 [2] 45 cb [2] 47 ca [2] 5c cc [2] 40 cb [2] 5c e4 }

  condition:
    any of them
}