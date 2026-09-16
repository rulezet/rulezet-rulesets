rule TTP_XOR_QUAD_CurrentVersionRun_2a96 {
  strings:
    $key_2a96 = { 79 f9 [2] 5d f7 [2] 76 db [2] 58 f9 [2] 4c e2 [2] 43 f8 [2] 5d e5 [2] 5f e4 [2] 44 e2 [2] 58 e5 [2] 44 ca }

  condition:
    any of them
}