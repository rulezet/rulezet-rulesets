rule TTP_XOR_QUAD_CurrentVersionRun_adae {
  strings:
    $key_adae = { fe c1 [2] da cf [2] f1 e3 [2] df c1 [2] cb da [2] c4 c0 [2] da dd [2] d8 dc [2] c3 da [2] df dd [2] c3 f2 }

  condition:
    any of them
}