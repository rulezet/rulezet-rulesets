rule TTP_XOR_QUAD_CurrentVersionRun_bbb4 {
  strings:
    $key_bbb4 = { e8 db [2] cc d5 [2] e7 f9 [2] c9 db [2] dd c0 [2] d2 da [2] cc c7 [2] ce c6 [2] d5 c0 [2] c9 c7 [2] d5 e8 }

  condition:
    any of them
}