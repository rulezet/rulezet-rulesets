rule TTP_XOR_QUAD_CurrentVersionRun_369b {
  strings:
    $key_369b = { 65 f4 [2] 41 fa [2] 6a d6 [2] 44 f4 [2] 50 ef [2] 5f f5 [2] 41 e8 [2] 43 e9 [2] 58 ef [2] 44 e8 [2] 58 c7 }

  condition:
    any of them
}