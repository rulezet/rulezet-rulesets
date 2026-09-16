rule TTP_XOR_QUAD_CurrentVersionRun_aeac {
  strings:
    $key_aeac = { fd c3 [2] d9 cd [2] f2 e1 [2] dc c3 [2] c8 d8 [2] c7 c2 [2] d9 df [2] db de [2] c0 d8 [2] dc df [2] c0 f0 }

  condition:
    any of them
}