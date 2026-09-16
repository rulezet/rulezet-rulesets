rule TTP_XOR_QUAD_CurrentVersionRun_1996 {
  strings:
    $key_1996 = { 4a f9 [2] 6e f7 [2] 45 db [2] 6b f9 [2] 7f e2 [2] 70 f8 [2] 6e e5 [2] 6c e4 [2] 77 e2 [2] 6b e5 [2] 77 ca }

  condition:
    any of them
}