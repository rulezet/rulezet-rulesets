rule TTP_XOR_QUAD_CurrentVersionRun_db89 {
  strings:
    $key_db89 = { 88 e6 [2] ac e8 [2] 87 c4 [2] a9 e6 [2] bd fd [2] b2 e7 [2] ac fa [2] ae fb [2] b5 fd [2] a9 fa [2] b5 d5 }

  condition:
    any of them
}