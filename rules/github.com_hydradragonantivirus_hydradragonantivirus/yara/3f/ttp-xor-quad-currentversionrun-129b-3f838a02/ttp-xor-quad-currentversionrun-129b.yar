rule TTP_XOR_QUAD_CurrentVersionRun_129b {
  strings:
    $key_129b = { 41 f4 [2] 65 fa [2] 4e d6 [2] 60 f4 [2] 74 ef [2] 7b f5 [2] 65 e8 [2] 67 e9 [2] 7c ef [2] 60 e8 [2] 7c c7 }

  condition:
    any of them
}