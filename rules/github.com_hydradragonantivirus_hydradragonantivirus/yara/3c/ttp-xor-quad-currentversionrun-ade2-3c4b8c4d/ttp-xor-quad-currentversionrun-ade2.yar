rule TTP_XOR_QUAD_CurrentVersionRun_ade2 {
  strings:
    $key_ade2 = { fe 8d [2] da 83 [2] f1 af [2] df 8d [2] cb 96 [2] c4 8c [2] da 91 [2] d8 90 [2] c3 96 [2] df 91 [2] c3 be }

  condition:
    any of them
}