rule TTP_XOR_QUAD_CurrentVersionRun_c0a7 {
  strings:
    $key_c0a7 = { 93 c8 [2] b7 c6 [2] 9c ea [2] b2 c8 [2] a6 d3 [2] a9 c9 [2] b7 d4 [2] b5 d5 [2] ae d3 [2] b2 d4 [2] ae fb }

  condition:
    any of them
}