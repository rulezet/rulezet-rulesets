rule TTP_XOR_QUAD_CurrentVersionRun_b9ac {
  strings:
    $key_b9ac = { ea c3 [2] ce cd [2] e5 e1 [2] cb c3 [2] df d8 [2] d0 c2 [2] ce df [2] cc de [2] d7 d8 [2] cb df [2] d7 f0 }

  condition:
    any of them
}