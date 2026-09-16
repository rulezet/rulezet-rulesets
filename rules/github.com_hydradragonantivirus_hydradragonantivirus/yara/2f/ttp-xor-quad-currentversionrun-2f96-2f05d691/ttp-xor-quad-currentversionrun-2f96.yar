rule TTP_XOR_QUAD_CurrentVersionRun_2f96 {
  strings:
    $key_2f96 = { 7c f9 [2] 58 f7 [2] 73 db [2] 5d f9 [2] 49 e2 [2] 46 f8 [2] 58 e5 [2] 5a e4 [2] 41 e2 [2] 5d e5 [2] 41 ca }

  condition:
    any of them
}