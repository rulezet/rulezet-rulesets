rule TTP_XOR_QUAD_CurrentVersionRun_dc88 {
  strings:
    $key_dc88 = { 8f e7 [2] ab e9 [2] 80 c5 [2] ae e7 [2] ba fc [2] b5 e6 [2] ab fb [2] a9 fa [2] b2 fc [2] ae fb [2] b2 d4 }

  condition:
    any of them
}