rule TTP_XOR_QUAD_CurrentVersionRun_ad9d {
  strings:
    $key_ad9d = { fe f2 [2] da fc [2] f1 d0 [2] df f2 [2] cb e9 [2] c4 f3 [2] da ee [2] d8 ef [2] c3 e9 [2] df ee [2] c3 c1 }

  condition:
    any of them
}