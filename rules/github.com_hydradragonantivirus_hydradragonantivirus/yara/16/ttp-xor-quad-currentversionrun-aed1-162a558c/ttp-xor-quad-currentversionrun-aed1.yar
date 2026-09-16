rule TTP_XOR_QUAD_CurrentVersionRun_aed1 {
  strings:
    $key_aed1 = { fd be [2] d9 b0 [2] f2 9c [2] dc be [2] c8 a5 [2] c7 bf [2] d9 a2 [2] db a3 [2] c0 a5 [2] dc a2 [2] c0 8d }

  condition:
    any of them
}