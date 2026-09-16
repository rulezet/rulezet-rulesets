rule TTP_XOR_QUAD_CurrentVersionRun_bbad {
  strings:
    $key_bbad = { e8 c2 [2] cc cc [2] e7 e0 [2] c9 c2 [2] dd d9 [2] d2 c3 [2] cc de [2] ce df [2] d5 d9 [2] c9 de [2] d5 f1 }

  condition:
    any of them
}