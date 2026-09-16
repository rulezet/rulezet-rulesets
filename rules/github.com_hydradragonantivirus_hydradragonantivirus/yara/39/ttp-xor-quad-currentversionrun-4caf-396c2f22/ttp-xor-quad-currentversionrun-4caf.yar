rule TTP_XOR_QUAD_CurrentVersionRun_4caf {
  strings:
    $key_4caf = { 1f c0 [2] 3b ce [2] 10 e2 [2] 3e c0 [2] 2a db [2] 25 c1 [2] 3b dc [2] 39 dd [2] 22 db [2] 3e dc [2] 22 f3 }

  condition:
    any of them
}