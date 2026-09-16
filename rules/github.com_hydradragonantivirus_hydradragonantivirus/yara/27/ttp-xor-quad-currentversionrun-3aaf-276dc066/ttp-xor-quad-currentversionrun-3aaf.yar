rule TTP_XOR_QUAD_CurrentVersionRun_3aaf {
  strings:
    $key_3aaf = { 69 c0 [2] 4d ce [2] 66 e2 [2] 48 c0 [2] 5c db [2] 53 c1 [2] 4d dc [2] 4f dd [2] 54 db [2] 48 dc [2] 54 f3 }

  condition:
    any of them
}