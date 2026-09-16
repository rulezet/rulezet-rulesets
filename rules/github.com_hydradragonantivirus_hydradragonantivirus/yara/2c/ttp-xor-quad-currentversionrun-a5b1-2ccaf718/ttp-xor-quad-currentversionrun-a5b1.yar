rule TTP_XOR_QUAD_CurrentVersionRun_a5b1 {
  strings:
    $key_a5b1 = { f6 de [2] d2 d0 [2] f9 fc [2] d7 de [2] c3 c5 [2] cc df [2] d2 c2 [2] d0 c3 [2] cb c5 [2] d7 c2 [2] cb ed }

  condition:
    any of them
}