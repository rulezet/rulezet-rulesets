rule TTP_XOR_QUAD_CurrentVersionRun_49af {
  strings:
    $key_49af = { 1a c0 [2] 3e ce [2] 15 e2 [2] 3b c0 [2] 2f db [2] 20 c1 [2] 3e dc [2] 3c dd [2] 27 db [2] 3b dc [2] 27 f3 }

  condition:
    any of them
}