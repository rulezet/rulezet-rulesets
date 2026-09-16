rule TTP_XOR_QUAD_CurrentVersionRun_38ba {
  strings:
    $key_38ba = { 6b d5 [2] 4f db [2] 64 f7 [2] 4a d5 [2] 5e ce [2] 51 d4 [2] 4f c9 [2] 4d c8 [2] 56 ce [2] 4a c9 [2] 56 e6 }

  condition:
    any of them
}