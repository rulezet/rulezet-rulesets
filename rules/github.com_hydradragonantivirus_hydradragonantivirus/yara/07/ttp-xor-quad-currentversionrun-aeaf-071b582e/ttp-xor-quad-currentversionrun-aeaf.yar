rule TTP_XOR_QUAD_CurrentVersionRun_aeaf {
  strings:
    $key_aeaf = { fd c0 [2] d9 ce [2] f2 e2 [2] dc c0 [2] c8 db [2] c7 c1 [2] d9 dc [2] db dd [2] c0 db [2] dc dc [2] c0 f3 }

  condition:
    any of them
}