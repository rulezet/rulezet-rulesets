rule TTP_XOR_QUAD_CurrentVersionRun_69af {
  strings:
    $key_69af = { 3a c0 [2] 1e ce [2] 35 e2 [2] 1b c0 [2] 0f db [2] 00 c1 [2] 1e dc [2] 1c dd [2] 07 db [2] 1b dc [2] 07 f3 }

  condition:
    any of them
}