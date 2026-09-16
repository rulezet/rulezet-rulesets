rule TTP_XOR_QUAD_CurrentVersionRun_59af {
  strings:
    $key_59af = { 0a c0 [2] 2e ce [2] 05 e2 [2] 2b c0 [2] 3f db [2] 30 c1 [2] 2e dc [2] 2c dd [2] 37 db [2] 2b dc [2] 37 f3 }

  condition:
    any of them
}