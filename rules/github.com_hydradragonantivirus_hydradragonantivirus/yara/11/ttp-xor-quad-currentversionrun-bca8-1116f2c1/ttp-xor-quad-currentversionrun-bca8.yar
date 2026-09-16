rule TTP_XOR_QUAD_CurrentVersionRun_bca8 {
  strings:
    $key_bca8 = { ef c7 [2] cb c9 [2] e0 e5 [2] ce c7 [2] da dc [2] d5 c6 [2] cb db [2] c9 da [2] d2 dc [2] ce db [2] d2 f4 }

  condition:
    any of them
}