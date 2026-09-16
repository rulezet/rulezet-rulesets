rule TTP_XOR_QUAD_CurrentVersionRun_bcb5 {
  strings:
    $key_bcb5 = { ef da [2] cb d4 [2] e0 f8 [2] ce da [2] da c1 [2] d5 db [2] cb c6 [2] c9 c7 [2] d2 c1 [2] ce c6 [2] d2 e9 }

  condition:
    any of them
}