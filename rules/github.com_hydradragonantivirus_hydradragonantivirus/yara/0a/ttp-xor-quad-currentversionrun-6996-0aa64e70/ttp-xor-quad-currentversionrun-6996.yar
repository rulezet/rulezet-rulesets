rule TTP_XOR_QUAD_CurrentVersionRun_6996 {
  strings:
    $key_6996 = { 3a f9 [2] 1e f7 [2] 35 db [2] 1b f9 [2] 0f e2 [2] 00 f8 [2] 1e e5 [2] 1c e4 [2] 07 e2 [2] 1b e5 [2] 07 ca }

  condition:
    any of them
}