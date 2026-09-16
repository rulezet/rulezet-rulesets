rule TTP_XOR_QUAD_CurrentVersionRun_65ba {
  strings:
    $key_65ba = { 36 d5 [2] 12 db [2] 39 f7 [2] 17 d5 [2] 03 ce [2] 0c d4 [2] 12 c9 [2] 10 c8 [2] 0b ce [2] 17 c9 [2] 0b e6 }

  condition:
    any of them
}