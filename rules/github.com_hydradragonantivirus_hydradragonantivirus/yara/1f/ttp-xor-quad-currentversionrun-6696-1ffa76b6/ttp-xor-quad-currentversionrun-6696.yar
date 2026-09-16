rule TTP_XOR_QUAD_CurrentVersionRun_6696 {
  strings:
    $key_6696 = { 35 f9 [2] 11 f7 [2] 3a db [2] 14 f9 [2] 00 e2 [2] 0f f8 [2] 11 e5 [2] 13 e4 [2] 08 e2 [2] 14 e5 [2] 08 ca }

  condition:
    any of them
}