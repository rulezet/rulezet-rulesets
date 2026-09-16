rule TTP_XOR_QUAD_CurrentVersionRun_bec3 {
  strings:
    $key_bec3 = { ed ac [2] c9 a2 [2] e2 8e [2] cc ac [2] d8 b7 [2] d7 ad [2] c9 b0 [2] cb b1 [2] d0 b7 [2] cc b0 [2] d0 9f }

  condition:
    any of them
}