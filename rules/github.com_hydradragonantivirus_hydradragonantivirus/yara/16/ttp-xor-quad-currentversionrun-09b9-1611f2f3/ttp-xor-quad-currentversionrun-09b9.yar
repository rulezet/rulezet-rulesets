rule TTP_XOR_QUAD_CurrentVersionRun_09b9 {
  strings:
    $key_09b9 = { 5a d6 [2] 7e d8 [2] 55 f4 [2] 7b d6 [2] 6f cd [2] 60 d7 [2] 7e ca [2] 7c cb [2] 67 cd [2] 7b ca [2] 67 e5 }

  condition:
    any of them
}