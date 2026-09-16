rule TTP_XOR_QUAD_CurrentVersionRun_7a96 {
  strings:
    $key_7a96 = { 29 f9 [2] 0d f7 [2] 26 db [2] 08 f9 [2] 1c e2 [2] 13 f8 [2] 0d e5 [2] 0f e4 [2] 14 e2 [2] 08 e5 [2] 14 ca }

  condition:
    any of them
}