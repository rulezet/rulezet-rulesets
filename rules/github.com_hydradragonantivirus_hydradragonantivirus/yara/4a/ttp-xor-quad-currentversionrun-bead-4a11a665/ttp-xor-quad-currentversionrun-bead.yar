rule TTP_XOR_QUAD_CurrentVersionRun_bead {
  strings:
    $key_bead = { ed c2 [2] c9 cc [2] e2 e0 [2] cc c2 [2] d8 d9 [2] d7 c3 [2] c9 de [2] cb df [2] d0 d9 [2] cc de [2] d0 f1 }

  condition:
    any of them
}