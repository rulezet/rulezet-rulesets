rule TTP_XOR_QUAD_CurrentVersionRun_fd94 {
  strings:
    $key_fd94 = { ae fb [2] 8a f5 [2] a1 d9 [2] 8f fb [2] 9b e0 [2] 94 fa [2] 8a e7 [2] 88 e6 [2] 93 e0 [2] 8f e7 [2] 93 c8 }

  condition:
    any of them
}