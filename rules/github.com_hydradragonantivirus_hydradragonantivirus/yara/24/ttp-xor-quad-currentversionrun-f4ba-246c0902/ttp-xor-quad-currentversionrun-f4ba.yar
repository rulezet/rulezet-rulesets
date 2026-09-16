rule TTP_XOR_QUAD_CurrentVersionRun_f4ba {
  strings:
    $key_f4ba = { a7 d5 [2] 83 db [2] a8 f7 [2] 86 d5 [2] 92 ce [2] 9d d4 [2] 83 c9 [2] 81 c8 [2] 9a ce [2] 86 c9 [2] 9a e6 }

  condition:
    any of them
}