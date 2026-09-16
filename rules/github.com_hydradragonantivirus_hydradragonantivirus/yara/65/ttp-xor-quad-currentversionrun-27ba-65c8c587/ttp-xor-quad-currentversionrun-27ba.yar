rule TTP_XOR_QUAD_CurrentVersionRun_27ba {
  strings:
    $key_27ba = { 74 d5 [2] 50 db [2] 7b f7 [2] 55 d5 [2] 41 ce [2] 4e d4 [2] 50 c9 [2] 52 c8 [2] 49 ce [2] 55 c9 [2] 49 e6 }

  condition:
    any of them
}