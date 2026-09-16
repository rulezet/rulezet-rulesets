rule TTP_XOR_QUAD_CurrentVersionRun_57b9 {
  strings:
    $key_57b9 = { 04 d6 [2] 20 d8 [2] 0b f4 [2] 25 d6 [2] 31 cd [2] 3e d7 [2] 20 ca [2] 22 cb [2] 39 cd [2] 25 ca [2] 39 e5 }

  condition:
    any of them
}