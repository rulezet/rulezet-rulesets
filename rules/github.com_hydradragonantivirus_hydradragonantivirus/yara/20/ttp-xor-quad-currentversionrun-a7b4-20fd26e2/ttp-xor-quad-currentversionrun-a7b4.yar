rule TTP_XOR_QUAD_CurrentVersionRun_a7b4 {
  strings:
    $key_a7b4 = { f4 db [2] d0 d5 [2] fb f9 [2] d5 db [2] c1 c0 [2] ce da [2] d0 c7 [2] d2 c6 [2] c9 c0 [2] d5 c7 [2] c9 e8 }

  condition:
    any of them
}