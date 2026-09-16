rule TTP_XOR_QUAD_CurrentVersionRun_18b9 {
  strings:
    $key_18b9 = { 4b d6 [2] 6f d8 [2] 44 f4 [2] 6a d6 [2] 7e cd [2] 71 d7 [2] 6f ca [2] 6d cb [2] 76 cd [2] 6a ca [2] 76 e5 }

  condition:
    any of them
}