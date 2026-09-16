rule TTP_XOR_QUAD_CurrentVersionRun_3987 {
  strings:
    $key_3987 = { 6a e8 [2] 4e e6 [2] 65 ca [2] 4b e8 [2] 5f f3 [2] 50 e9 [2] 4e f4 [2] 4c f5 [2] 57 f3 [2] 4b f4 [2] 57 db }

  condition:
    any of them
}