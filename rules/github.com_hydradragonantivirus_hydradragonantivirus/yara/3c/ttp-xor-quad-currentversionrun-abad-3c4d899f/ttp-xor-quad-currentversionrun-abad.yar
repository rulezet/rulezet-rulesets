rule TTP_XOR_QUAD_CurrentVersionRun_abad {
  strings:
    $key_abad = { f8 c2 [2] dc cc [2] f7 e0 [2] d9 c2 [2] cd d9 [2] c2 c3 [2] dc de [2] de df [2] c5 d9 [2] d9 de [2] c5 f1 }

  condition:
    any of them
}