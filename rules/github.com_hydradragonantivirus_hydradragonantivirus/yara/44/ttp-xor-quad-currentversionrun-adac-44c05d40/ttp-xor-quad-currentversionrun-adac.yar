rule TTP_XOR_QUAD_CurrentVersionRun_adac {
  strings:
    $key_adac = { fe c3 [2] da cd [2] f1 e1 [2] df c3 [2] cb d8 [2] c4 c2 [2] da df [2] d8 de [2] c3 d8 [2] df df [2] c3 f0 }

  condition:
    any of them
}