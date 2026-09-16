rule TTP_XOR_QUAD_CurrentVersionRun_1187 {
  strings:
    $key_1187 = { 42 e8 [2] 66 e6 [2] 4d ca [2] 63 e8 [2] 77 f3 [2] 78 e9 [2] 66 f4 [2] 64 f5 [2] 7f f3 [2] 63 f4 [2] 7f db }

  condition:
    any of them
}