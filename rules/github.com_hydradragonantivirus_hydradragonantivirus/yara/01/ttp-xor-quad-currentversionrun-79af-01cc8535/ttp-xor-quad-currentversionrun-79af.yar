rule TTP_XOR_QUAD_CurrentVersionRun_79af {
  strings:
    $key_79af = { 2a c0 [2] 0e ce [2] 25 e2 [2] 0b c0 [2] 1f db [2] 10 c1 [2] 0e dc [2] 0c dd [2] 17 db [2] 0b dc [2] 17 f3 }

  condition:
    any of them
}