rule TTP_XOR_QUAD_CurrentVersionRun_bbaf {
  strings:
    $key_bbaf = { e8 c0 [2] cc ce [2] e7 e2 [2] c9 c0 [2] dd db [2] d2 c1 [2] cc dc [2] ce dd [2] d5 db [2] c9 dc [2] d5 f3 }

  condition:
    any of them
}