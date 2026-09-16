rule TTP_XOR_QUAD_CurrentVersionRun_0db9 {
  strings:
    $key_0db9 = { 5e d6 [2] 7a d8 [2] 51 f4 [2] 7f d6 [2] 6b cd [2] 64 d7 [2] 7a ca [2] 78 cb [2] 63 cd [2] 7f ca [2] 63 e5 }

  condition:
    any of them
}