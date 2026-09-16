rule TTP_XOR_QUAD_CurrentVersionRun_acae {
  strings:
    $key_acae = { ff c1 [2] db cf [2] f0 e3 [2] de c1 [2] ca da [2] c5 c0 [2] db dd [2] d9 dc [2] c2 da [2] de dd [2] c2 f2 }

  condition:
    any of them
}