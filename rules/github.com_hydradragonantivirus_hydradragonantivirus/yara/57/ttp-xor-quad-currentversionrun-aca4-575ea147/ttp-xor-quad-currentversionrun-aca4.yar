rule TTP_XOR_QUAD_CurrentVersionRun_aca4 {
  strings:
    $key_aca4 = { ff cb [2] db c5 [2] f0 e9 [2] de cb [2] ca d0 [2] c5 ca [2] db d7 [2] d9 d6 [2] c2 d0 [2] de d7 [2] c2 f8 }

  condition:
    any of them
}