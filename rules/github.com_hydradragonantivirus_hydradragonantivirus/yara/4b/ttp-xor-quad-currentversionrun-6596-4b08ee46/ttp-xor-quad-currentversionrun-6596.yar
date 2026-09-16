rule TTP_XOR_QUAD_CurrentVersionRun_6596 {
  strings:
    $key_6596 = { 36 f9 [2] 12 f7 [2] 39 db [2] 17 f9 [2] 03 e2 [2] 0c f8 [2] 12 e5 [2] 10 e4 [2] 0b e2 [2] 17 e5 [2] 0b ca }

  condition:
    any of them
}