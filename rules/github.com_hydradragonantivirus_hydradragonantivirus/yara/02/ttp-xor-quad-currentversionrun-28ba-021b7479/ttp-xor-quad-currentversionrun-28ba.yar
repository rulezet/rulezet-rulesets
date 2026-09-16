rule TTP_XOR_QUAD_CurrentVersionRun_28ba {
  strings:
    $key_28ba = { 7b d5 [2] 5f db [2] 74 f7 [2] 5a d5 [2] 4e ce [2] 41 d4 [2] 5f c9 [2] 5d c8 [2] 46 ce [2] 5a c9 [2] 46 e6 }

  condition:
    any of them
}