rule TTP_XOR_QUAD_CurrentVersionRun_37b8 {
  strings:
    $key_37b8 = { 64 d7 [2] 40 d9 [2] 6b f5 [2] 45 d7 [2] 51 cc [2] 5e d6 [2] 40 cb [2] 42 ca [2] 59 cc [2] 45 cb [2] 59 e4 }

  condition:
    any of them
}