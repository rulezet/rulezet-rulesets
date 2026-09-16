rule TTP_XOR_QUAD_CurrentVersionRun_ad81 {
  strings:
    $key_ad81 = { fe ee [2] da e0 [2] f1 cc [2] df ee [2] cb f5 [2] c4 ef [2] da f2 [2] d8 f3 [2] c3 f5 [2] df f2 [2] c3 dd }

  condition:
    any of them
}