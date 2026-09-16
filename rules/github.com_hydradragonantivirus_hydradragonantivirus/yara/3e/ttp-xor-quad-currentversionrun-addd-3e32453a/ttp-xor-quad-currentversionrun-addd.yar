rule TTP_XOR_QUAD_CurrentVersionRun_addd {
  strings:
    $key_addd = { fe b2 [2] da bc [2] f1 90 [2] df b2 [2] cb a9 [2] c4 b3 [2] da ae [2] d8 af [2] c3 a9 [2] df ae [2] c3 81 }

  condition:
    any of them
}