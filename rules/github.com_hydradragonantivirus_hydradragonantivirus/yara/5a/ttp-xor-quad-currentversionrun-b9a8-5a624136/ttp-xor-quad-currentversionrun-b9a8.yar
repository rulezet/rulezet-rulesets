rule TTP_XOR_QUAD_CurrentVersionRun_b9a8 {
  strings:
    $key_b9a8 = { ea c7 [2] ce c9 [2] e5 e5 [2] cb c7 [2] df dc [2] d0 c6 [2] ce db [2] cc da [2] d7 dc [2] cb db [2] d7 f4 }

  condition:
    any of them
}