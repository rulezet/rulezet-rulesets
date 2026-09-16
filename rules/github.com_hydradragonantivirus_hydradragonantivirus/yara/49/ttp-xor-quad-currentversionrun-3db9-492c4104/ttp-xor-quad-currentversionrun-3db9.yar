rule TTP_XOR_QUAD_CurrentVersionRun_3db9 {
  strings:
    $key_3db9 = { 6e d6 [2] 4a d8 [2] 61 f4 [2] 4f d6 [2] 5b cd [2] 54 d7 [2] 4a ca [2] 48 cb [2] 53 cd [2] 4f ca [2] 53 e5 }

  condition:
    any of them
}