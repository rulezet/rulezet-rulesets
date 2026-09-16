rule TTP_XOR_QUAD_CurrentVersionRun_369a {
  strings:
    $key_369a = { 65 f5 [2] 41 fb [2] 6a d7 [2] 44 f5 [2] 50 ee [2] 5f f4 [2] 41 e9 [2] 43 e8 [2] 58 ee [2] 44 e9 [2] 58 c6 }

  condition:
    any of them
}