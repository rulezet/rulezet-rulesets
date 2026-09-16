rule TTP_XOR_QUAD_CurrentVersionRun_e387 {
  strings:
    $key_e387 = { b0 e8 [2] 94 e6 [2] bf ca [2] 91 e8 [2] 85 f3 [2] 8a e9 [2] 94 f4 [2] 96 f5 [2] 8d f3 [2] 91 f4 [2] 8d db }

  condition:
    any of them
}