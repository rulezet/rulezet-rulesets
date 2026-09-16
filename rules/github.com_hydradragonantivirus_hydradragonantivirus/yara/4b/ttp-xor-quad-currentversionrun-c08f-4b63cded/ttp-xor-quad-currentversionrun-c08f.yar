rule TTP_XOR_QUAD_CurrentVersionRun_c08f {
  strings:
    $key_c08f = { 93 e0 [2] b7 ee [2] 9c c2 [2] b2 e0 [2] a6 fb [2] a9 e1 [2] b7 fc [2] b5 fd [2] ae fb [2] b2 fc [2] ae d3 }

  condition:
    any of them
}