rule TTP_XOR_QUAD_CurrentVersionRun_8da8 {
  strings:
    $key_8da8 = { de c7 [2] fa c9 [2] d1 e5 [2] ff c7 [2] eb dc [2] e4 c6 [2] fa db [2] f8 da [2] e3 dc [2] ff db [2] e3 f4 }

  condition:
    any of them
}