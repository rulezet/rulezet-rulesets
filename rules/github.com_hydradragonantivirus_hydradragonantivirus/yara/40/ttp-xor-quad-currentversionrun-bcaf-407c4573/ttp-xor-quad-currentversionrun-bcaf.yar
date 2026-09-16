rule TTP_XOR_QUAD_CurrentVersionRun_bcaf {
  strings:
    $key_bcaf = { ef c0 [2] cb ce [2] e0 e2 [2] ce c0 [2] da db [2] d5 c1 [2] cb dc [2] c9 dd [2] d2 db [2] ce dc [2] d2 f3 }

  condition:
    any of them
}