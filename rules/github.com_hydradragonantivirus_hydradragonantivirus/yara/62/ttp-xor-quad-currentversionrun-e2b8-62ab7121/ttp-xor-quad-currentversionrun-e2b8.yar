rule TTP_XOR_QUAD_CurrentVersionRun_e2b8 {
  strings:
    $key_e2b8 = { b1 d7 [2] 95 d9 [2] be f5 [2] 90 d7 [2] 84 cc [2] 8b d6 [2] 95 cb [2] 97 ca [2] 8c cc [2] 90 cb [2] 8c e4 }

  condition:
    any of them
}