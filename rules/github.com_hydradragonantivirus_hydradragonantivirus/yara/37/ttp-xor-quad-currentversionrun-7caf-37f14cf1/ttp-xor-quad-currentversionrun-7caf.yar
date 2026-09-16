rule TTP_XOR_QUAD_CurrentVersionRun_7caf {
  strings:
    $key_7caf = { 2f c0 [2] 0b ce [2] 20 e2 [2] 0e c0 [2] 1a db [2] 15 c1 [2] 0b dc [2] 09 dd [2] 12 db [2] 0e dc [2] 12 f3 }

  condition:
    any of them
}