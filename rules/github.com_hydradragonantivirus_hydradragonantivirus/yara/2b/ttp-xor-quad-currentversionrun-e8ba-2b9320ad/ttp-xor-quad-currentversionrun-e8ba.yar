rule TTP_XOR_QUAD_CurrentVersionRun_e8ba {
  strings:
    $key_e8ba = { bb d5 [2] 9f db [2] b4 f7 [2] 9a d5 [2] 8e ce [2] 81 d4 [2] 9f c9 [2] 9d c8 [2] 86 ce [2] 9a c9 [2] 86 e6 }

  condition:
    any of them
}