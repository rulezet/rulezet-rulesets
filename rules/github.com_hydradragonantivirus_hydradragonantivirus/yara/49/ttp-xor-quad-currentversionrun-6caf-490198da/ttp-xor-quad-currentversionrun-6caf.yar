rule TTP_XOR_QUAD_CurrentVersionRun_6caf {
  strings:
    $key_6caf = { 3f c0 [2] 1b ce [2] 30 e2 [2] 1e c0 [2] 0a db [2] 05 c1 [2] 1b dc [2] 19 dd [2] 02 db [2] 1e dc [2] 02 f3 }

  condition:
    any of them
}