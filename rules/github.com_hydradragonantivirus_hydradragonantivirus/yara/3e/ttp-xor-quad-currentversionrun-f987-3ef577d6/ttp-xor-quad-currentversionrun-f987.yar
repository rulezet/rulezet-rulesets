rule TTP_XOR_QUAD_CurrentVersionRun_f987 {
  strings:
    $key_f987 = { aa e8 [2] 8e e6 [2] a5 ca [2] 8b e8 [2] 9f f3 [2] 90 e9 [2] 8e f4 [2] 8c f5 [2] 97 f3 [2] 8b f4 [2] 97 db }

  condition:
    any of them
}