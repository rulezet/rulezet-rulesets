rule TTP_XOR_QUAD_CurrentVersionRun_bea8 {
  strings:
    $key_bea8 = { ed c7 [2] c9 c9 [2] e2 e5 [2] cc c7 [2] d8 dc [2] d7 c6 [2] c9 db [2] cb da [2] d0 dc [2] cc db [2] d0 f4 }

  condition:
    any of them
}