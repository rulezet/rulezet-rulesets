rule TTP_XOR_QUAD_CurrentVersionRun_39ba {
  strings:
    $key_39ba = { 6a d5 [2] 4e db [2] 65 f7 [2] 4b d5 [2] 5f ce [2] 50 d4 [2] 4e c9 [2] 4c c8 [2] 57 ce [2] 4b c9 [2] 57 e6 }

  condition:
    any of them
}