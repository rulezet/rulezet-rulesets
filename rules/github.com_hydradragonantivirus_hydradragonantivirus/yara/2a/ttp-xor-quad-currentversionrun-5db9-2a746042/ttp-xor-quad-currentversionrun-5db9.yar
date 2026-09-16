rule TTP_XOR_QUAD_CurrentVersionRun_5db9 {
  strings:
    $key_5db9 = { 0e d6 [2] 2a d8 [2] 01 f4 [2] 2f d6 [2] 3b cd [2] 34 d7 [2] 2a ca [2] 28 cb [2] 33 cd [2] 2f ca [2] 33 e5 }

  condition:
    any of them
}