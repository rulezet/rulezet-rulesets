rule TTP_XOR_QUAD_CurrentVersionRun_28b9 {
  strings:
    $key_28b9 = { 7b d6 [2] 5f d8 [2] 74 f4 [2] 5a d6 [2] 4e cd [2] 41 d7 [2] 5f ca [2] 5d cb [2] 46 cd [2] 5a ca [2] 46 e5 }

  condition:
    any of them
}