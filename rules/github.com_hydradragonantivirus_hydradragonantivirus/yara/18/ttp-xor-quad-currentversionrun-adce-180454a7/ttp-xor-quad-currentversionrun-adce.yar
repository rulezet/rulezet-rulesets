rule TTP_XOR_QUAD_CurrentVersionRun_adce {
  strings:
    $key_adce = { fe a1 [2] da af [2] f1 83 [2] df a1 [2] cb ba [2] c4 a0 [2] da bd [2] d8 bc [2] c3 ba [2] df bd [2] c3 92 }

  condition:
    any of them
}