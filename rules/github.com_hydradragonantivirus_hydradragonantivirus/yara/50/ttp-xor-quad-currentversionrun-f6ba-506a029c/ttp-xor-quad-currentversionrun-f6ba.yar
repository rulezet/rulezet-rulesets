rule TTP_XOR_QUAD_CurrentVersionRun_f6ba {
  strings:
    $key_f6ba = { a5 d5 [2] 81 db [2] aa f7 [2] 84 d5 [2] 90 ce [2] 9f d4 [2] 81 c9 [2] 83 c8 [2] 98 ce [2] 84 c9 [2] 98 e6 }

  condition:
    any of them
}