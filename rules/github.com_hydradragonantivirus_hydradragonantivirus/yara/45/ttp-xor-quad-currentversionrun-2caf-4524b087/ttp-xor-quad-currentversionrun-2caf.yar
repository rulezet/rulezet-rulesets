rule TTP_XOR_QUAD_CurrentVersionRun_2caf {
  strings:
    $key_2caf = { 7f c0 [2] 5b ce [2] 70 e2 [2] 5e c0 [2] 4a db [2] 45 c1 [2] 5b dc [2] 59 dd [2] 42 db [2] 5e dc [2] 42 f3 }

  condition:
    any of them
}