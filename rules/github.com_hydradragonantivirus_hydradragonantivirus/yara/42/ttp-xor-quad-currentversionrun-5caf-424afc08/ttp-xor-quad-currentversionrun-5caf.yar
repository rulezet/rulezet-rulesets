rule TTP_XOR_QUAD_CurrentVersionRun_5caf {
  strings:
    $key_5caf = { 0f c0 [2] 2b ce [2] 00 e2 [2] 2e c0 [2] 3a db [2] 35 c1 [2] 2b dc [2] 29 dd [2] 32 db [2] 2e dc [2] 32 f3 }

  condition:
    any of them
}