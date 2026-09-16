rule TTP_XOR_QUAD_CurrentVersionRun_379b {
  strings:
    $key_379b = { 64 f4 [2] 40 fa [2] 6b d6 [2] 45 f4 [2] 51 ef [2] 5e f5 [2] 40 e8 [2] 42 e9 [2] 59 ef [2] 45 e8 [2] 59 c7 }

  condition:
    any of them
}