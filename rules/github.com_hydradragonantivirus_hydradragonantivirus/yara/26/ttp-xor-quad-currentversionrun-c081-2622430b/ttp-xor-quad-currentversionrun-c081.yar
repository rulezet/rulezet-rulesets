rule TTP_XOR_QUAD_CurrentVersionRun_c081 {
  strings:
    $key_c081 = { 93 ee [2] b7 e0 [2] 9c cc [2] b2 ee [2] a6 f5 [2] a9 ef [2] b7 f2 [2] b5 f3 [2] ae f5 [2] b2 f2 [2] ae dd }

  condition:
    any of them
}