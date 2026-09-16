rule TTP_XOR_QUAD_CurrentVersionRun_2996 {
  strings:
    $key_2996 = { 7a f9 [2] 5e f7 [2] 75 db [2] 5b f9 [2] 4f e2 [2] 40 f8 [2] 5e e5 [2] 5c e4 [2] 47 e2 [2] 5b e5 [2] 47 ca }

  condition:
    any of them
}