rule TTP_XOR_QUAD_CurrentVersionRun_f2b6 {
  strings:
    $key_f2b6 = { a1 d9 [2] 85 d7 [2] ae fb [2] 80 d9 [2] 94 c2 [2] 9b d8 [2] 85 c5 [2] 87 c4 [2] 9c c2 [2] 80 c5 [2] 9c ea }

  condition:
    any of them
}