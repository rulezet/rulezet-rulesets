rule TTP_XOR_QUAD_CurrentVersionRun_acce {
  strings:
    $key_acce = { ff a1 [2] db af [2] f0 83 [2] de a1 [2] ca ba [2] c5 a0 [2] db bd [2] d9 bc [2] c2 ba [2] de bd [2] c2 92 }

  condition:
    any of them
}