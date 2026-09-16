rule TTP_XOR_QUAD_CurrentVersionRun_b0a8 {
  strings:
    $key_b0a8 = { e3 c7 [2] c7 c9 [2] ec e5 [2] c2 c7 [2] d6 dc [2] d9 c6 [2] c7 db [2] c5 da [2] de dc [2] c2 db [2] de f4 }

  condition:
    any of them
}