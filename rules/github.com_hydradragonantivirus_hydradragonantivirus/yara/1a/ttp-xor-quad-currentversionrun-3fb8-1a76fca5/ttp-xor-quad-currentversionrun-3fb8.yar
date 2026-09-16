rule TTP_XOR_QUAD_CurrentVersionRun_3fb8 {
  strings:
    $key_3fb8 = { 6c d7 [2] 48 d9 [2] 63 f5 [2] 4d d7 [2] 59 cc [2] 56 d6 [2] 48 cb [2] 4a ca [2] 51 cc [2] 4d cb [2] 51 e4 }

  condition:
    any of them
}