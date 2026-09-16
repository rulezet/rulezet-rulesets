rule TTP_XOR_QUAD_CurrentVersionRun_18ba {
  strings:
    $key_18ba = { 4b d5 [2] 6f db [2] 44 f7 [2] 6a d5 [2] 7e ce [2] 71 d4 [2] 6f c9 [2] 6d c8 [2] 76 ce [2] 6a c9 [2] 76 e6 }

  condition:
    any of them
}