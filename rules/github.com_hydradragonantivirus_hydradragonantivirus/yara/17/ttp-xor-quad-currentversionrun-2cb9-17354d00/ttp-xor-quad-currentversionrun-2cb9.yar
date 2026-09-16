rule TTP_XOR_QUAD_CurrentVersionRun_2cb9 {
  strings:
    $key_2cb9 = { 7f d6 [2] 5b d8 [2] 70 f4 [2] 5e d6 [2] 4a cd [2] 45 d7 [2] 5b ca [2] 59 cb [2] 42 cd [2] 5e ca [2] 42 e5 }

  condition:
    any of them
}