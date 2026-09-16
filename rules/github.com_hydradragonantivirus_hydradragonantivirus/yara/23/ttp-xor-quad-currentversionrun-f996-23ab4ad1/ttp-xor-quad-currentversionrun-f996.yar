rule TTP_XOR_QUAD_CurrentVersionRun_f996 {
  strings:
    $key_f996 = { aa f9 [2] 8e f7 [2] a5 db [2] 8b f9 [2] 9f e2 [2] 90 f8 [2] 8e e5 [2] 8c e4 [2] 97 e2 [2] 8b e5 [2] 97 ca }

  condition:
    any of them
}