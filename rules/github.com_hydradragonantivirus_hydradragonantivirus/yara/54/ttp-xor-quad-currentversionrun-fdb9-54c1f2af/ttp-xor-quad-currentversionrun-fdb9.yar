rule TTP_XOR_QUAD_CurrentVersionRun_fdb9 {
  strings:
    $key_fdb9 = { ae d6 [2] 8a d8 [2] a1 f4 [2] 8f d6 [2] 9b cd [2] 94 d7 [2] 8a ca [2] 88 cb [2] 93 cd [2] 8f ca [2] 93 e5 }

  condition:
    any of them
}