rule TTP_XOR_QUAD_CurrentVersionRun_acd1 {
  strings:
    $key_acd1 = { ff be [2] db b0 [2] f0 9c [2] de be [2] ca a5 [2] c5 bf [2] db a2 [2] d9 a3 [2] c2 a5 [2] de a2 [2] c2 8d }

  condition:
    any of them
}