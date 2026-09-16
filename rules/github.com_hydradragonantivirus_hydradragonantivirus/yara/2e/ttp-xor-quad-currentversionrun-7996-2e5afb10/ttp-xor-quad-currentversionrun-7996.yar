rule TTP_XOR_QUAD_CurrentVersionRun_7996 {
  strings:
    $key_7996 = { 2a f9 [2] 0e f7 [2] 25 db [2] 0b f9 [2] 1f e2 [2] 10 f8 [2] 0e e5 [2] 0c e4 [2] 17 e2 [2] 0b e5 [2] 17 ca }

  condition:
    any of them
}