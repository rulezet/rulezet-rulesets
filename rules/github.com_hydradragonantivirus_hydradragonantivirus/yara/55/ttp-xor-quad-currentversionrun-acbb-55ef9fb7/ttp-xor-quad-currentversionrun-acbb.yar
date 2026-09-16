rule TTP_XOR_QUAD_CurrentVersionRun_acbb {
  strings:
    $key_acbb = { ff d4 [2] db da [2] f0 f6 [2] de d4 [2] ca cf [2] c5 d5 [2] db c8 [2] d9 c9 [2] c2 cf [2] de c8 [2] c2 e7 }

  condition:
    any of them
}