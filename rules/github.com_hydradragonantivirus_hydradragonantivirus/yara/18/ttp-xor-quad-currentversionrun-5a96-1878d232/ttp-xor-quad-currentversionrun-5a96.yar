rule TTP_XOR_QUAD_CurrentVersionRun_5a96 {
  strings:
    $key_5a96 = { 09 f9 [2] 2d f7 [2] 06 db [2] 28 f9 [2] 3c e2 [2] 33 f8 [2] 2d e5 [2] 2f e4 [2] 34 e2 [2] 28 e5 [2] 34 ca }

  condition:
    any of them
}