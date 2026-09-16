rule TTP_XOR_QUAD_CurrentVersionRun_12b4 {
  strings:
    $key_12b4 = { 41 db [2] 65 d5 [2] 4e f9 [2] 60 db [2] 74 c0 [2] 7b da [2] 65 c7 [2] 67 c6 [2] 7c c0 [2] 60 c7 [2] 7c e8 }

  condition:
    any of them
}